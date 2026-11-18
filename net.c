#include "net.h"
#include <stdio.h>
#include <string.h>
#include "pico/stdlib.h"
#include "pico/cyw43_arch.h"
#include "lwip/tcp.h"
#include "lwip/ip4_addr.h"
#include "lwip/dhcp.h"
#include "lwip/netif.h"

#define REQ_MAX   1024
#define RESP_MAX  1024
#define REQ_TIMEOUT_MS   6000
#define RECONNECT_MS     20000
#define DHCP_PATIENCE_MS 90000   // associated but no IP yet: wait this long before restarting the join

static struct {
    const char *ssid, *ssid_alt, *password;
    bool use_alt;
    bool initialised, connecting;
    absolute_time_t next_attempt;
    absolute_time_t join_started;
    char ip[16];
} W;

static struct {
    struct tcp_pcb *pcb;
    char req[REQ_MAX];  uint16_t req_len;
    char resp[RESP_MAX]; uint16_t resp_len;
    volatile bool busy, done;
    net_cb_t cb; void *user;
    absolute_time_t deadline;
} R;

/* ---------------------------------------------------------------- Wi-Fi link */
// Optional fixed address (set by net_set_static_ip before net_start). Some
// hotspots, iPhones in particular, associate the board but never answer its
// DHCP request; a static address on the hotspot's subnet sidesteps that.
static struct { bool set; ip4_addr_t ip, mask, gw; } ST;

void net_set_static_ip(const char *ip, const char *mask, const char *gw) {
    ST.set = ip4addr_aton(ip, &ST.ip) && ip4addr_aton(mask, &ST.mask) && ip4addr_aton(gw, &ST.gw);
    if (!ST.set) printf("WIFI,static ip config invalid, using DHCP\n");
}

static void net_apply_static_ip(void) {
    if (!ST.set) return;
    cyw43_arch_lwip_begin();
    struct netif *n = &cyw43_state.netif[CYW43_ITF_STA];
    dhcp_stop(n);
    netif_set_addr(n, &ST.ip, &ST.mask, &ST.gw);
    cyw43_arch_lwip_end();
    printf("WIFI,static ip %s\n", ip4addr_ntoa(&ST.ip));
}
void net_start(const char *ssid, const char *ssid_alt, const char *password) {
    W.ssid = ssid; W.ssid_alt = (ssid_alt && ssid_alt[0]) ? ssid_alt : NULL; W.password = password;
    if (cyw43_arch_init()) { printf("WIFI,init failed\n"); return; }
    cyw43_arch_enable_sta_mode();
    net_apply_static_ip();
    // Power save off: with it on, the CYW43 can sleep through DHCP replies and
    // incoming packets, which showed up as "joined, waiting for an IP" forever.
    // Story #113 (power optimisation) will revisit this with measurements.
    cyw43_wifi_pm(&cyw43_state, CYW43_NONE_PM);
    W.initialised = true;
    W.next_attempt = get_absolute_time();
    strcpy(W.ip, "-");
}

static void try_connect(void) {
    const char *ssid = (W.use_alt && W.ssid_alt) ? W.ssid_alt : W.ssid;
    int rc = cyw43_arch_wifi_connect_async(ssid, W.password, CYW43_AUTH_WPA2_AES_PSK);
    W.connecting = (rc == 0);
    W.join_started = get_absolute_time();
    W.next_attempt = make_timeout_time_ms(RECONNECT_MS);
    printf("WIFI,connecting to \"%s\"%s%s\n", ssid, W.use_alt ? " (alternate spelling)" : "", rc ? " (start failed)" : "");
}

bool net_connected(void) {
    if (!W.initialised) return false;
    return cyw43_tcpip_link_status(&cyw43_state, CYW43_ITF_STA) == CYW43_LINK_UP;
}

const char *net_ip(void) { return W.ip; }
bool net_busy(void) { return R.busy; }

/* ---------------------------------------------------------------- HTTP POST */
static void req_close(void) {
    if (R.pcb) {
        tcp_arg(R.pcb, NULL); tcp_recv(R.pcb, NULL); tcp_err(R.pcb, NULL); tcp_sent(R.pcb, NULL);
        if (tcp_close(R.pcb) != ERR_OK) tcp_abort(R.pcb);
        R.pcb = NULL;
    }
}

// Drop a request that did not complete. tcp_close() on a connection with data
// still in flight keeps the pcb and its segments alive for minutes of
// retransmission; a burst of such requests exhausted the 4 KB lwIP heap and
// silenced the reader for ~5 min at a time. tcp_abort() frees everything now.
static void req_abort(void) {
    if (R.pcb) {
        tcp_arg(R.pcb, NULL); tcp_recv(R.pcb, NULL); tcp_err(R.pcb, NULL); tcp_sent(R.pcb, NULL);
        tcp_abort(R.pcb);
        R.pcb = NULL;
    }
}

static void req_finish(void) {        // lwIP context: just mark done, main loop dispatches
    req_close();
    R.done = true;
}

static err_t on_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err) {
    (void)arg; (void)err;
    if (!p) { req_finish(); return ERR_OK; }           // server closed: response complete
    uint16_t room = RESP_MAX - 1 - R.resp_len;
    uint16_t n = p->tot_len < room ? p->tot_len : room;
    pbuf_copy_partial(p, R.resp + R.resp_len, n, 0);
    R.resp_len += n; R.resp[R.resp_len] = 0;
    tcp_recved(pcb, p->tot_len);
    pbuf_free(p);
    return ERR_OK;
}

static void on_err(void *arg, err_t err) {           // pcb already freed by lwIP
    (void)arg; (void)err;
    R.pcb = NULL;
    R.done = true;
}

static err_t on_connected(void *arg, struct tcp_pcb *pcb, err_t err) {
    (void)arg;
    if (err != ERR_OK) { req_abort(); R.done = true; return ERR_ABRT; }
    if (tcp_write(pcb, R.req, R.req_len, TCP_WRITE_FLAG_COPY) != ERR_OK) {
        // No room to queue the request (heap or segment pool full): give up at
        // once rather than holding the connection open until the deadline.
        req_abort(); R.done = true; return ERR_ABRT;
    }
    tcp_output(pcb);
    return ERR_OK;
}

bool net_post(const char *host, uint16_t port, const char *path, const char *device_key,
              const char *json, net_cb_t cb, void *user) {
    if (R.busy || !net_connected()) return false;
    int n = snprintf(R.req, REQ_MAX,
                     "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\n"
                     "X-Device-Key: %s\r\nContent-Length: %u\r\nConnection: close\r\n\r\n%s",
                     path, host, device_key, (unsigned)strlen(json), json);
    if (n <= 0 || n >= REQ_MAX) return false;
    R.req_len = (uint16_t)n; R.resp_len = 0; R.resp[0] = 0;
    R.cb = cb; R.user = user; R.done = false;

    ip_addr_t ip;
    if (!ip4addr_aton(host, &ip)) return false;
    cyw43_arch_lwip_begin();
    R.pcb = tcp_new();
    bool ok = R.pcb != NULL;
    if (ok) {
        tcp_arg(R.pcb, &R); tcp_recv(R.pcb, on_recv); tcp_err(R.pcb, on_err);
        ok = tcp_connect(R.pcb, &ip, port, on_connected) == ERR_OK;
        if (!ok) req_close();
    }
    cyw43_arch_lwip_end();
    if (!ok) return false;
    R.busy = true;
    R.deadline = make_timeout_time_ms(REQ_TIMEOUT_MS);
    return true;
}

static int parse_status(const char *resp) {
    int code = 0;
    if (sscanf(resp, "HTTP/%*d.%*d %d", &code) == 1) return code;
    return 0;
}

/* ---------------------------------------------------------------- main-loop driver */
void net_poll(void) {
    if (!W.initialised) return;

    // link management
    int st = cyw43_tcpip_link_status(&cyw43_state, CYW43_ITF_STA);
    if (st == CYW43_LINK_UP) {
        if (W.connecting) {
            W.connecting = false;
            const ip4_addr_t *a = netif_ip4_addr(netif_default);
            strncpy(W.ip, a ? ip4addr_ntoa(a) : "?", sizeof(W.ip) - 1);
            printf("WIFI,connected,%s\n", W.ip);
        }
    } else {
        if (strcmp(W.ip, "-") != 0) { printf("WIFI,disconnected\n"); strcpy(W.ip, "-"); }
        if (time_reached(W.next_attempt)) {
            int ws = cyw43_wifi_link_status(&cyw43_state, CYW43_ITF_STA);
            // Associated and waiting for DHCP: restarting the join would restart
            // DHCP too. Give it time; only report progress.
            if ((ws == CYW43_LINK_JOIN || ws == CYW43_LINK_NOIP) &&
                absolute_time_diff_us(W.join_started, get_absolute_time()) < (int64_t)DHCP_PATIENCE_MS * 1000) {
                printf("WIFI,joined, waiting for an IP address (%lu s)\n",
                       (unsigned long)(absolute_time_diff_us(W.join_started, get_absolute_time()) / 1000000));
                W.next_attempt = make_timeout_time_ms(10000);
                return;
            }
            // Say why the last attempt did not get a link before trying again.
            const char *why = ws == CYW43_LINK_NONET ? "network not found (2.4 GHz on? name exact?)"
                            : ws == CYW43_LINK_BADAUTH ? "wrong password"
                            : ws == CYW43_LINK_FAIL ? "join failed"
                            : ws == CYW43_LINK_JOIN ? "joined, waiting for IP (DHCP)"
                            : ws == CYW43_LINK_NOIP ? "joined, no IP yet"
                            : ws == CYW43_LINK_DOWN ? "link down" : "status unknown";
            printf("WIFI,last attempt: %s (%d)\n", why, ws);
            if (ws == CYW43_LINK_NONET && W.ssid_alt) W.use_alt = !W.use_alt;   // try the other spelling
            try_connect();
        }
    }

    // request completion / timeout
    if (R.busy) {
        if (!R.done && time_reached(R.deadline)) {
            cyw43_arch_lwip_begin(); req_abort(); cyw43_arch_lwip_end();
            R.done = true; R.resp_len = 0; R.resp[0] = 0;
        }
        if (R.done) {
            R.busy = false;
            int status = parse_status(R.resp);
            const char *body = strstr(R.resp, "\r\n\r\n");
            if (R.cb) R.cb(status, body ? body + 4 : "", R.user);
        }
    }
}
