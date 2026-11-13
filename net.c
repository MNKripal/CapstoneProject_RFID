#include "net.h"
#include <stdio.h>
#include <string.h>
#include "pico/stdlib.h"
#include "pico/cyw43_arch.h"
#include "lwip/tcp.h"
#include "lwip/ip4_addr.h"

#define REQ_MAX   1024
#define RESP_MAX  1024
#define REQ_TIMEOUT_MS   6000
#define RECONNECT_MS     10000

static struct {
    const char *ssid, *password;
    bool initialised, connecting;
    absolute_time_t next_attempt;
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
void net_start(const char *ssid, const char *password) {
    W.ssid = ssid; W.password = password;
    if (cyw43_arch_init()) { printf("WIFI,init failed\n"); return; }
    cyw43_arch_enable_sta_mode();
    cyw43_wifi_pm(&cyw43_state, CYW43_PERFORMANCE_PM);
    W.initialised = true;
    W.next_attempt = get_absolute_time();
    strcpy(W.ip, "-");
}

static void try_connect(void) {
    int rc = cyw43_arch_wifi_connect_async(W.ssid, W.password, CYW43_AUTH_WPA2_AES_PSK);
    W.connecting = (rc == 0);
    W.next_attempt = make_timeout_time_ms(RECONNECT_MS);
    printf("WIFI,connecting to %s%s\n", W.ssid, rc ? " (start failed)" : "");
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
    if (err != ERR_OK) { req_finish(); return err; }
    tcp_write(pcb, R.req, R.req_len, TCP_WRITE_FLAG_COPY);
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
        if (time_reached(W.next_attempt)) try_connect();
    }

    // request completion / timeout
    if (R.busy) {
        if (!R.done && time_reached(R.deadline)) {
            cyw43_arch_lwip_begin(); req_close(); cyw43_arch_lwip_end();
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
