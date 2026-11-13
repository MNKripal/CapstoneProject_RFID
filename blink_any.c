#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "pico/stdio_usb.h"
#include "pico/stdlib.h"
#include "hardware/spi.h"
#include "pico/rand.h"
#include "mfrc522.h"

// Wi-Fi is compiled in only when wifi_config.h exists (copy wifi_config.example.h).
#if __has_include("wifi_config.h")
#include "wifi_config.h"
#include "net.h"
#define WIFI_ENABLED 1
#endif

/* ---------------------------------------------------------------------------
 * RFID Reader Wiring Configuration
 *
 * Define the GPIO pins used to connect the MFRC522 RFID reader to the
 * Raspberry Pi Pico 2 W. This is the ONLY place pins are defined; update
 * these definitions to match the actual wiring.
 *
 *   MFRC522 Pin       Pico 2 W Connection
 *   -------------------------------------
 *   SDA (NSS)         PIN_CS
 *   SCK               PIN_SCK
 *   MOSI              PIN_MOSI
 *   MISO              PIN_MISO
 *   RST               PIN_RST
 *   3.3V              3V3 OUT, pin 36 (do NOT use 5V)
 *   GND               GND
 *
 * Ensure that SCK, MOSI, and MISO use GPIO pins supported by the selected
 * SPI interface.
 *
 * Valid SPI0 GPIO options:
 *   SCK:   GPIO 2, 6, or 18
 *   MOSI:  GPIO 3, 7, or 19
 *   MISO:  GPIO 4, 16, or 20
 *
 * Current project wiring (matches the defines below and README.md):
 *   SCK  = GPIO 2    MOSI = GPIO 3    MISO = GPIO 4
 *   CS   = GPIO 5    RST  = GPIO 15
 * ------------------------------------------------------------------------- */
#define SPI_PORT  spi0
#define PIN_SCK   2
#define PIN_MOSI  3
#define PIN_MISO  4
#define PIN_CS    5
#define PIN_RST   15

// The RC522 supports up to 10 MHz. 1 MHz is plenty and tolerant of long
// jumper wires / breadboards.
#define SPI_BAUD_HZ (1000 * 1000)

// Antenna drivers: 0x03 = TX1 + TX2 (full drive, best range), 0x01 = TX1 only
// (about half the transmitter current). Full drive is the default. If the chip
// resets repeatedly (a weak 3.3 V feed sagging when a card loads the antenna,
// measured with RFID_DIAG W5), the loop drops to TX1 only for a while and then
// tries full drive again, so range is only given up while it has to be.
#define ANTENNA_TX_FULL        0x03
#define ANTENNA_TX_REDUCED     0x01
#define STORM_RESETS           3       // this many recoveries ...
#define STORM_WINDOW_MS        1000    // ... within this window => reduce drive
#define REDUCED_DRIVE_MS       15000   // how long to stay reduced before retrying full

// How often to poll for a card, and how often to verify the reader is alive.
#define POLL_INTERVAL_MS      50
#define HEALTH_CHECK_MS       1000
// How long the SAME card is ignored after a successful read (a halted card
// does not answer REQA anyway; this covers cards that fail to halt). The
// holdoff is tracked per UID, so other cards are never held back.
#define REREAD_HOLDOFF_MS     1500
#define RECENT_MAX            8
// Cards read back to back within one poll. Each read card is halted, so the
// next request is answered by the next card still awake in the field.
#define MAX_CARDS_PER_POLL    8
// Heartbeat interval. The dashboard marks a reader offline when it stops
// hearing these (see dashboard/server.py OFFLINE_AFTER_S).
#define HEARTBEAT_MS          30000
// Scans are kept in memory until the host acknowledges them (ACK,<seq>) and
// are re-sent at this interval, so a disconnected laptop or a server restart
// does not lose a read. PENDING_MAX bounds the memory; oldest is dropped first.
#define RESEND_MS             3000
#define PENDING_MAX           64
// Over Wi-Fi, how soon after one scan upload the next may start.
#define NET_SEND_GAP_MS       250
// How many times to retry the UID read within one poll when the card answered
// the request but the anticollision step failed (card still moving in).
#define UID_READ_RETRIES      2

// Identifier of this reader station. Each physical reader is bolted to a known
// bike rack; the dashboard maps this ID to a campus location (dashboard/readers.json).
#define READER_ID "rack-01"

static const uint8_t AUTHORIZED_UID[] = {0xDE, 0xAD, 0xBE, 0xEF};
#define AUTHORIZED_UID_LEN (sizeof(AUTHORIZED_UID) / sizeof(AUTHORIZED_UID[0]))

/* ---------------------------------------------------------------------------
 * Acknowledged scan buffer.
 *
 * Every scan gets a sequence number and is printed as
 *   SCAN,<reader_id>,<uid hex>,<1|0>,<boot_id hex>,<seq>
 * It stays in `pending` until the host writes "ACK,<seq>" back over the same
 * serial port; until then it is re-printed every RESEND_MS. boot_id is random
 * per power-up so <reader_id>-<boot_id>-<seq> is a unique id for the event
 * even across reboots (the server uses it to drop duplicates).
 * ------------------------------------------------------------------------- */
typedef struct {
    bool     used;
    uint32_t seq;
    uint8_t  uid[10];
    uint8_t  size;
    bool     authorized;
} pending_scan_t;

static pending_scan_t pending[PENDING_MAX];
static uint32_t next_seq = 1;
static uint32_t boot_id;
static uint32_t dropped_scans = 0;

static void print_scan(const pending_scan_t *p) {
    printf("SCAN,%s,", READER_ID);
    for (uint8_t i = 0; i < p->size; i++) printf("%02X", p->uid[i]);
    printf(",%d,%08lX,%lu\n", p->authorized ? 1 : 0, (unsigned long)boot_id, (unsigned long)p->seq);
}

static uint32_t pending_count(void) {
    uint32_t n = 0;
    for (int i = 0; i < PENDING_MAX; i++) if (pending[i].used) n++;
    return n;
}

static void pending_add(const Uid *uid, bool authorized) {
    int slot = -1;
    for (int i = 0; i < PENDING_MAX; i++) if (!pending[i].used) { slot = i; break; }
    if (slot < 0) {   // full: drop the oldest so the newest read is kept
        slot = 0;
        for (int i = 1; i < PENDING_MAX; i++) if (pending[i].seq < pending[slot].seq) slot = i;
        dropped_scans++;
        printf("WARN,%s,buffer full, dropped scan seq %lu (host not acknowledging)\n", READER_ID, (unsigned long)pending[slot].seq);
    }
    pending_scan_t *p = &pending[slot];
    p->used = true; p->seq = next_seq++; p->size = uid->size; p->authorized = authorized;
    memcpy(p->uid, uid->uidByte, uid->size);
    print_scan(p);
}

static void pending_ack(uint32_t seq) {
    for (int i = 0; i < PENDING_MAX; i++) if (pending[i].used && pending[i].seq == seq) pending[i].used = false;
}

static void pending_resend(void) {
    // oldest first, so the host sees events in order
    for (;;) {
        int best = -1;
        for (int i = 0; i < PENDING_MAX; i++)
            if (pending[i].used && !(pending[i].seq & 0x80000000u) && (best < 0 || pending[i].seq < pending[best].seq)) best = i;
        if (best < 0) break;
        print_scan(&pending[best]);
        pending[best].seq |= 0x80000000u;   // mark visited for this pass
    }
    for (int i = 0; i < PENDING_MAX; i++) pending[i].seq &= 0x7FFFFFFFu;
}

static pending_scan_t *pending_oldest(void) {
    int best = -1;
    for (int i = 0; i < PENDING_MAX; i++)
        if (pending[i].used && (best < 0 || pending[i].seq < pending[best].seq)) best = i;
    return best < 0 ? NULL : &pending[best];
}

#ifdef WIFI_ENABLED
/* ---------------------------------------------------------------------------
 * Wi-Fi upload: the server's reply is the acknowledgement, and its verdict
 * (from the tag registry) is printed as SERVER,... so it can drive the lock.
 * ------------------------------------------------------------------------- */
static uint32_t net_recoveries_ref;   // set from main so heartbeats can report it
static uint32_t inflight_seq;

static void on_scan_posted(int status, const char *body, void *user) {
    uint32_t seq = (uint32_t)(uintptr_t)user;
    inflight_seq = 0;
    if (status == 200 || status == 201) {
        pending_ack(seq);
        bool auth = strstr(body, "\"authorized\": true") != NULL;
        printf("SERVER,%s,seq=%lu,%s%s\n", READER_ID, (unsigned long)seq, auth ? "AUTHORIZED" : "DENIED",
               strstr(body, "\"duplicate\": true") ? ",duplicate" : "");
    } else {
        printf("WIFI,scan upload failed (status %d), will retry\n", status);
    }
}

static void on_hb_posted(int status, const char *body, void *user) {
    (void)body; (void)user;
    if (status != 200) printf("WIFI,heartbeat failed (status %d)\n", status);
}

static bool net_send_oldest_scan(void) {
    pending_scan_t *p = pending_oldest();
    if (!p) return false;
    char uid[21]; int n = 0;
    for (uint8_t i = 0; i < p->size; i++) n += snprintf(uid + n, sizeof(uid) - n, "%02X", p->uid[i]);
    char json[160];
    snprintf(json, sizeof(json),
             "{\"reader_id\":\"%s\",\"uid\":\"%s\",\"device_authorized\":%s,\"event_id\":\"%s-%08lX-%lu\"}",
             READER_ID, uid, p->authorized ? "true" : "false", READER_ID, (unsigned long)boot_id, (unsigned long)p->seq);
    if (net_post(SERVER_HOST, SERVER_PORT, "/api/scans", DEVICE_KEY, json, on_scan_posted, (void *)(uintptr_t)p->seq)) {
        inflight_seq = p->seq;
        return true;
    }
    return false;
}

static void net_send_heartbeat(void) {
    char json[160];
    snprintf(json, sizeof(json), "{\"reader_id\":\"%s\",\"pending\":%lu,\"dropped\":%lu,\"recoveries\":%lu,\"uptime_s\":%lu}",
             READER_ID, (unsigned long)pending_count(), (unsigned long)dropped_scans,
             (unsigned long)net_recoveries_ref, (unsigned long)(to_ms_since_boot(get_absolute_time()) / 1000));
    net_post(SERVER_HOST, SERVER_PORT, "/api/heartbeat", DEVICE_KEY, json, on_hb_posted, NULL);
}
#endif

// Read whatever the host has typed/sent, one line at a time, without blocking.
static void poll_host_input(void) {
    static char line[32];
    static uint8_t len = 0;
    for (int guard = 0; guard < 64; guard++) {
        int c = getchar_timeout_us(0);
        if (c == PICO_ERROR_TIMEOUT || c < 0) return;
        if (c == '\r') continue;
        if (c != '\n') { if (len < sizeof(line) - 1) line[len++] = (char)c; continue; }
        line[len] = 0; len = 0;
        if (strncmp(line, "ACK,", 4) == 0) {
            pending_ack((uint32_t)strtoul(line + 4, NULL, 10));
        } else if (strcmp(line, "RESEND") == 0) {
            pending_resend();
        } else if (strcmp(line, "HELLO") == 0) {
            printf("BOOT,%s,%08lX,pending=%lu\n", READER_ID, (unsigned long)boot_id, (unsigned long)pending_count());
        }
    }
}

static void setup_spi(void) {
    spi_init(SPI_PORT, SPI_BAUD_HZ);
    // RC522 uses SPI mode 0 (CPOL=0, CPHA=0), MSB first.
    spi_set_format(SPI_PORT, 8, SPI_CPOL_0, SPI_CPHA_0, SPI_MSB_FIRST);
    gpio_set_function(PIN_SCK, GPIO_FUNC_SPI);
    gpio_set_function(PIN_MOSI, GPIO_FUNC_SPI);
    gpio_set_function(PIN_MISO, GPIO_FUNC_SPI);
}

// Initialise the reader and keep retrying until it answers on the bus.
// Returns only when the reader is up, so the main loop never runs against a
// dead chip.
static void init_reader_blocking(MFRC522Ptr_t mfrc) {
    int attempt = 0;
    while (true) {
        attempt++;
        PCD_Init(mfrc);
        if (PCD_IsHealthy(mfrc)) {
            printf("RC522 ready after %d attempt(s). ", attempt);
            PCD_DumpVersionToSerial(mfrc);
            return;
        }
        printf("RC522 not responding (attempt %d). ", attempt);
        PCD_DumpVersionToSerial(mfrc);
        printf("  Check wiring: SDA->GPIO%d SCK->GPIO%d MOSI->GPIO%d "
               "MISO->GPIO%d RST->GPIO%d, 3.3V, GND\n",
               PIN_CS, PIN_SCK, PIN_MOSI, PIN_MISO, PIN_RST);
        sleep_ms(1000);
    }
}

/* ---------------------------------------------------------------------------
 * Per-tag debounce: remember recently read UIDs and when their holdoff ends.
 * ------------------------------------------------------------------------- */
typedef struct {
    uint8_t uid[10];
    uint8_t size;
    absolute_time_t until;
} recent_t;
static recent_t recent[RECENT_MAX];

static bool same_uid(const recent_t *r, const Uid *u) {
    return r->size == u->size && memcmp(r->uid, u->uidByte, u->size) == 0;
}

static bool recently_seen(const Uid *u) {
    for (int i = 0; i < RECENT_MAX; i++)
        if (recent[i].size && same_uid(&recent[i], u) && !time_reached(recent[i].until)) return true;
    return false;
}

static void mark_seen(const Uid *u) {
    int slot = -1;
    for (int i = 0; i < RECENT_MAX; i++) if (recent[i].size && same_uid(&recent[i], u)) { slot = i; break; }
    if (slot < 0) for (int i = 0; i < RECENT_MAX; i++) if (!recent[i].size || time_reached(recent[i].until)) { slot = i; break; }
    if (slot < 0) {   // all busy: evict the one expiring soonest
        slot = 0;
        for (int i = 1; i < RECENT_MAX; i++)
            if (absolute_time_diff_us(recent[i].until, recent[slot].until) > 0) slot = i;
    }
    memcpy(recent[slot].uid, u->uidByte, u->size);
    recent[slot].size = u->size;
    recent[slot].until = make_timeout_time_ms(REREAD_HOLDOFF_MS);
}

// Read the UID; if the card answered the request but the anticollision step
// failed (typically a card still sliding into the field), wake it and retry
// a couple of times within this same poll instead of waiting for the next one.
static bool read_uid_with_retry(MFRC522Ptr_t mfrc) {
    if (PICC_ReadCardSerial(mfrc)) return true;
    for (int i = 0; i < UID_READ_RETRIES; i++) {
        sleep_ms(5);
        uint8_t atqa[2]; uint8_t n = sizeof(atqa);
        StatusCode st = PICC_WakeupA(mfrc, atqa, &n);
        if (st != STATUS_OK && st != STATUS_COLLISION) continue;
        if (PICC_ReadCardSerial(mfrc)) return true;
    }
    return false;
}

static bool uid_is_authorized(const Uid *uid) {
    if (uid->size != AUTHORIZED_UID_LEN) {
        return false;
    }
    for (uint8_t i = 0; i < uid->size; i++) {
        if (uid->uidByte[i] != AUTHORIZED_UID[i]) {
            return false;
        }
    }
    return true;
}

static void print_uid(const Uid *uid) {
    printf("Card UID: ");
    for (uint8_t i = 0; i < uid->size; i++) {
        printf("%02X%s", uid->uidByte[i], (i + 1 < uid->size) ? " " : "");
    }
    printf("  (SAK 0x%02X, %s)\n", uid->sak, PICC_GetTypeName(PICC_GetType(uid->sak)));
}

#ifdef RFID_DIAG
// Diagnostic mode (build with -DRFID_DIAG=ON). Bisects what makes the chip
// lose its configuration shortly after PCD_Init().
static bool diag_cfg_ok(MFRC522Ptr_t mfrc) {
    return (PCD_ReadRegister(mfrc, TModeReg) & 0x80) && ((PCD_ReadRegister(mfrc, TxControlReg) & 0x03) == 0x03);
}
// Sample the config at increasing delays; report the first sample where it is gone.
static void diag_sample(MFRC522Ptr_t mfrc, const char *label) {
    static const uint32_t at_ms[] = {0, 1, 5, 20, 50, 100, 200, 500, 1000, 2000, 3000};
    absolute_time_t t0 = get_absolute_time();
    for (unsigned i = 0; i < sizeof(at_ms) / sizeof(at_ms[0]); i++) {
        while (absolute_time_diff_us(t0, get_absolute_time()) < (int64_t)at_ms[i] * 1000) tight_loop_contents();
        if (!diag_cfg_ok(mfrc)) {
            printf("DIAG %-34s LOST by +%lu ms  (TMode=%02X TxCtl=%02X Cmd=%02X RFCfg=%02X Status1=%02X)\n", label,
                   (unsigned long)at_ms[i], PCD_ReadRegister(mfrc, TModeReg), PCD_ReadRegister(mfrc, TxControlReg),
                   PCD_ReadRegister(mfrc, CommandReg), PCD_ReadRegister(mfrc, RFCfgReg), PCD_ReadRegister(mfrc, Status1Reg));
            return;
        }
    }
    printf("DIAG %-34s ok for 3000 ms\n", label);
}
static void diag_soft_init(MFRC522Ptr_t mfrc, bool max_gain) {   // PCD_Init without the RST pulse
    PCD_Reset(mfrc);
    PCD_WriteRegister(mfrc, TxModeReg, 0x00); PCD_WriteRegister(mfrc, RxModeReg, 0x00); PCD_WriteRegister(mfrc, ModWidthReg, 0x26);
    PCD_WriteRegister(mfrc, TModeReg, 0x80); PCD_WriteRegister(mfrc, TPrescalerReg, 0xA9);
    PCD_WriteRegister(mfrc, TReloadRegH, 0x03); PCD_WriteRegister(mfrc, TReloadRegL, 0xE8);
    PCD_WriteRegister(mfrc, TxASKReg, 0x40); PCD_WriteRegister(mfrc, ModeReg, 0x3D);
    if (max_gain) PCD_SetAntennaGain(mfrc, RxGain_max);
    PCD_AntennaOn(mfrc);
}
static void diag_run(MFRC522Ptr_t mfrc) {
    PCD_Init(mfrc);                      diag_sample(mfrc, "A: PCD_Init, then nothing");
    PCD_Init(mfrc);                      diag_sample(mfrc, "A2: PCD_Init again");
    diag_soft_init(mfrc, true);          diag_sample(mfrc, "B: soft reset only, max gain");
    diag_soft_init(mfrc, false);         diag_sample(mfrc, "C: soft reset only, default gain");
    PCD_Init(mfrc); PCD_SetAntennaGain(mfrc, RxGain_avg); diag_sample(mfrc, "D: PCD_Init then gain back to avg");
    // E: the real loop. Poll for cards and check the config after every poll.
    PCD_Init(mfrc);
    absolute_time_t t0 = get_absolute_time(); uint32_t polls = 0; bool lost = false;
    while (absolute_time_diff_us(t0, get_absolute_time()) < 3000 * 1000) {
        PICC_IsNewCardPresent(mfrc); polls++;
        if (!diag_cfg_ok(mfrc)) {
            printf("DIAG E: PCD_Init + polling              LOST after %lu polls, +%lu ms (TMode=%02X TxCtl=%02X Cmd=%02X Err=%02X)\n",
                   (unsigned long)polls, (unsigned long)(absolute_time_diff_us(t0, get_absolute_time()) / 1000),
                   PCD_ReadRegister(mfrc, TModeReg), PCD_ReadRegister(mfrc, TxControlReg),
                   PCD_ReadRegister(mfrc, CommandReg), PCD_ReadRegister(mfrc, ErrorReg));
            lost = true; break;
        }
        sleep_ms(50);
    }
    if (!lost) printf("DIAG E: PCD_Init + polling              ok for 3000 ms (%lu polls)\n", (unsigned long)polls);
    // F: polling without the antenna gain change
    diag_soft_init(mfrc, false);
    t0 = get_absolute_time(); polls = 0; lost = false;
    while (absolute_time_diff_us(t0, get_absolute_time()) < 3000 * 1000) {
        PICC_IsNewCardPresent(mfrc); polls++;
        if (!diag_cfg_ok(mfrc)) {
            printf("DIAG F: default gain + polling           LOST after %lu polls, +%lu ms\n", (unsigned long)polls,
                   (unsigned long)(absolute_time_diff_us(t0, get_absolute_time()) / 1000));
            lost = true; break;
        }
        sleep_ms(50);
    }
    if (!lost) printf("DIAG F: default gain + polling           ok for 3000 ms (%lu polls)\n", (unsigned long)polls);
    // G: supply stress. 200 antenna on/off cycles, the largest current step the chip makes.
    PCD_Init(mfrc); uint32_t resets = 0;
    for (int i = 0; i < 200; i++) {
        PCD_AntennaOff(mfrc); sleep_ms(5); PCD_AntennaOn(mfrc); sleep_ms(10);
        if (!diag_cfg_ok(mfrc)) { resets++; PCD_Init(mfrc); }
    }
    printf("DIAG G: 200 antenna on/off cycles        %lu resets\n", (unsigned long)resets);
    printf("DIAG done\n");
}
#endif

int main(void) {
    stdio_init_all();
    sleep_ms(2000); // give USB-CDC time to enumerate so early logs are visible

    printf("\n=== RFID reader starting ===\n");
    printf("Initializing SPI on spi%d at %d kHz...\n",
           spi_get_index(SPI_PORT), SPI_BAUD_HZ / 1000);
    setup_spi();

    PCD_SetTxMask(ANTENNA_TX_FULL);
    MFRC522Ptr_t mfrc = MFRC522_Init(SPI_PORT, PIN_CS, PIN_RST);
    if (mfrc == NULL) {
        printf("FATAL: could not allocate MFRC522 instance\n");
        while (true) tight_loop_contents();
    }

#ifdef RFID_DIAG
    // Pre-init wiring diagnostic: do writes stick at all, and is RST really wired?
    {
        printf("DIAG W1: version with RST high: %02X\n", PCD_ReadRegister(mfrc, VersionReg));
        gpio_put(PIN_RST, 0); sleep_ms(20);
        printf("DIAG W2: version with RST held LOW: %02X  (00/FF = RST wired, chip off; 92 = RST wire NOT reaching the module)\n", PCD_ReadRegister(mfrc, VersionReg));
        gpio_put(PIN_RST, 1); sleep_ms(50);
        PCD_Reset(mfrc);
        for (int i = 0; i < 5; i++) {
            PCD_WriteRegister(mfrc, TModeReg, 0x80);
            uint8_t now = PCD_ReadRegister(mfrc, TModeReg);
            sleep_ms(10);
            uint8_t later = PCD_ReadRegister(mfrc, TModeReg);
            printf("DIAG W3.%d: wrote TModeReg=80, readback now=%02X after 10 ms=%02X  Cmd=%02X Status1=%02X\n",
                   i, now, later, PCD_ReadRegister(mfrc, CommandReg), PCD_ReadRegister(mfrc, Status1Reg));
        }
        // Antenna current experiments: does the chip survive with less TX current?
        struct { const char *name; uint8_t txctl; uint8_t gsn; uint8_t cwgsp; } tries[] = {
            {"TX1+TX2, default drive (GsN=88 CWGsP=20)", 0x83, 0x88, 0x20},
            {"TX1 only,  default drive",                 0x81, 0x88, 0x20},
            {"TX1+TX2, half drive (GsN=44 CWGsP=10)",    0x83, 0x44, 0x10},
            {"TX1+TX2, low drive (GsN=22 CWGsP=08)",     0x83, 0x22, 0x08},
            {"TX1 only,  low drive",                     0x81, 0x22, 0x08},
        };
        for (unsigned t = 0; t < sizeof(tries) / sizeof(tries[0]); t++) {
            PCD_Reset(mfrc);
            PCD_WriteRegister(mfrc, TModeReg, 0x80);
            PCD_WriteRegister(mfrc, GsNReg, tries[t].gsn);
            PCD_WriteRegister(mfrc, CWGsPReg, tries[t].cwgsp);
            PCD_WriteRegister(mfrc, TxControlReg, tries[t].txctl);
            int held = -1;
            for (int i = 0; i < 20; i++) {
                sleep_ms(50);
                if (PCD_ReadRegister(mfrc, TModeReg) != 0x80) { held = i * 50; break; }
            }
            if (held < 0) printf("DIAG W4: %-44s SURVIVED 1 s\n", tries[t].name);
            else          printf("DIAG W4: %-44s reset within %d ms\n", tries[t].name, held);
            PCD_WriteRegister(mfrc, TxControlReg, 0x80);
            sleep_ms(200);
        }
        // W5: same drive levels, but with a CARD held in the field (user holds a tag).
        // The loaded antenna draws more current; count how often the chip resets per level.
        printf("DIAG W5: hold a tag against the reader now...\n");
        sleep_ms(3000);
        for (unsigned t = 0; t < sizeof(tries) / sizeof(tries[0]); t++) {
            int resets = 0, cards = 0;
            absolute_time_t until = make_timeout_time_ms(4000);
            PCD_Configure(mfrc);
            PCD_WriteRegister(mfrc, GsNReg, tries[t].gsn);
            PCD_WriteRegister(mfrc, CWGsPReg, tries[t].cwgsp);
            PCD_WriteRegister(mfrc, TxControlReg, tries[t].txctl);
            while (!time_reached(until)) {
                if ((PCD_ReadRegister(mfrc, TxControlReg) & tries[t].txctl) != tries[t].txctl) {
                    resets++;
                    PCD_Configure(mfrc);
                    PCD_WriteRegister(mfrc, GsNReg, tries[t].gsn);
                    PCD_WriteRegister(mfrc, CWGsPReg, tries[t].cwgsp);
                    PCD_WriteRegister(mfrc, TxControlReg, tries[t].txctl);
                } else {
                    uint8_t atqa[2]; uint8_t n = 2;
                    StatusCode st = PICC_WakeupA(mfrc, atqa, &n);
                    if (st == STATUS_OK || st == STATUS_COLLISION) cards++;
                }
                sleep_ms(50);
            }
            printf("DIAG W5: %-44s %d resets, card answered %d times in 4 s\n", tries[t].name, resets, cards);
        }
        PCD_WriteRegister(mfrc, TxControlReg, 0x80);
    }
#endif
    init_reader_blocking(mfrc);
    boot_id = get_rand_32();
    printf("BOOT,%s,%08lX,pending=0\n", READER_ID, (unsigned long)boot_id);
#ifdef WIFI_ENABLED
    printf("WIFI,enabled,server=%s:%d\n", SERVER_HOST, SERVER_PORT);
    net_start(WIFI_SSID, WIFI_PASSWORD);
#else
    printf("WIFI,disabled (no wifi_config.h), USB serial only\n");
#endif
#ifdef RFID_DIAG
    diag_run(mfrc);
    PCD_Init(mfrc);
#endif
    printf("Waiting for cards...\n");

    absolute_time_t next_health_check = make_timeout_time_ms(HEALTH_CHECK_MS);
    absolute_time_t next_heartbeat = get_absolute_time();
    absolute_time_t next_resend = make_timeout_time_ms(RESEND_MS);
#ifdef WIFI_ENABLED
    absolute_time_t next_net_hb = make_timeout_time_ms(2000);
    absolute_time_t next_net_send = get_absolute_time();
#endif
    uint32_t consecutive_failures = 0;
    uint32_t recoveries = 0;
    // reset-storm detection for the adaptive antenna drive
    uint32_t storm_count = 0;
    absolute_time_t storm_window_end = make_timeout_time_ms(STORM_WINDOW_MS);
    absolute_time_t reduced_until = nil_time;

    while (true) {
        sleep_ms(POLL_INTERVAL_MS);

        // Machine-readable liveness line for dashboard/serial_bridge.py:
        //   HB,<reader_id>
        if (time_reached(next_heartbeat)) {
            next_heartbeat = make_timeout_time_ms(HEARTBEAT_MS);
            printf("HB,%s,pending=%lu,dropped=%lu\n", READER_ID, (unsigned long)pending_count(), (unsigned long)dropped_scans);
        }

        // Host side of the acknowledgement protocol, and periodic re-send of
        // anything not yet acknowledged.
        poll_host_input();
        if (time_reached(next_resend)) {
            next_resend = make_timeout_time_ms(RESEND_MS);
            if (stdio_usb_connected()) pending_resend();
        }

#ifdef WIFI_ENABLED
        // Wi-Fi path: one request at a time; heartbeats first, then the oldest
        // unacknowledged scan. The server's reply acknowledges it.
        net_poll();
        net_recoveries_ref = recoveries;
        if (net_connected() && !net_busy()) {
            if (time_reached(next_net_hb)) {
                next_net_hb = make_timeout_time_ms(HEARTBEAT_MS);
                net_send_heartbeat();
            } else if (time_reached(next_net_send) && net_send_oldest_scan()) {
                next_net_send = make_timeout_time_ms(NET_SEND_GAP_MS);
            }
        }
#endif

        // Confirm the chip still has our configuration. A cheap one-register
        // check runs on every poll (a chip reset clears the antenna-enable
        // bits, and we measured rare resets under the antenna's current step);
        // the full check runs once a second. Re-init only when the config is
        // actually gone, so the reader is never blinded by a blind timer reset.
        bool full_check = time_reached(next_health_check);
        if (full_check) next_health_check = make_timeout_time_ms(HEALTH_CHECK_MS);
        // Adaptive antenna drive: back to full drive once the reduced period is over.
        if (PCD_GetTxMask() == ANTENNA_TX_REDUCED && time_reached(reduced_until)) {
            PCD_SetTxMask(ANTENNA_TX_FULL);
            PCD_AntennaOn(mfrc);
            printf("ANTENNA,%s,full drive restored\n", READER_ID);
        }
        if (time_reached(storm_window_end)) { storm_window_end = make_timeout_time_ms(STORM_WINDOW_MS); storm_count = 0; }

        if ((PCD_ReadRegister(mfrc, TxControlReg) & 0x03) != PCD_GetTxMask() || (full_check && !PCD_IsHealthy(mfrc))) {
            recoveries++;
            if (++storm_count >= STORM_RESETS && PCD_GetTxMask() == ANTENNA_TX_FULL) {
                PCD_SetTxMask(ANTENNA_TX_REDUCED);
                reduced_until = make_timeout_time_ms(REDUCED_DRIVE_MS);
                printf("ANTENNA,%s,reset storm: reduced to TX1 only for %d s (check 3.3V/GND to the module)\n",
                       READER_ID, REDUCED_DRIVE_MS / 1000);
            }
            if (PCD_IsResponding(mfrc)) {
                // Chip is alive, only its registers were reset: soft re-configure
                // (a few ms) instead of a full hardware reset (~250 ms).
                PCD_Configure(mfrc);
                if (PCD_IsHealthy(mfrc)) {
                    printf("RC522 lost its configuration (recovery #%lu), re-configured\n", (unsigned long)recoveries);
                    consecutive_failures = 0;
                    continue;
                }
            }
            printf("RC522 not responding (recovery #%lu), full re-init...\n", (unsigned long)recoveries);
            init_reader_blocking(mfrc);
            consecutive_failures = 0;
            continue;
        }

        // Read every card currently in the field, back to back. A card that
        // was read is halted and stops answering, so the next request is
        // answered by the next one. Two tags presented together therefore log
        // within a few tens of milliseconds of each other.
        for (int n = 0; n < MAX_CARDS_PER_POLL; n++) {
            if (!PICC_IsNewCardPresent(mfrc)) {
                break;
            }
            if (!read_uid_with_retry(mfrc)) {
                consecutive_failures++;
                printf("Card present but UID read failed (%lu in a row)\n",
                       (unsigned long)consecutive_failures);
                PCD_StopCrypto1(mfrc);
                if (consecutive_failures >= 5) {
                    // Something is wedged in the reader; a full re-init clears it.
                    printf("Too many failed reads, re-initializing RC522...\n");
                    init_reader_blocking(mfrc);
                    consecutive_failures = 0;
                }
                break;
            }
            consecutive_failures = 0;

            // Same card read again within its holdoff (it failed to halt, or a
            // retry's wake-up roused it): put it back to sleep, do not log.
            if (recently_seen(&mfrc->uid)) {
                PICC_HaltA(mfrc);
                PCD_StopCrypto1(mfrc);
                continue;
            }

            print_uid(&mfrc->uid);
            bool authorized = uid_is_authorized(&mfrc->uid);
            if (authorized) {
                printf(">>> AUTHORIZED: Bicycle Unlocked!\n");
            } else {
                printf(">>> DENIED: Unauthorized Tag.\n");
            }

            // Machine-readable log line consumed by dashboard/serial_bridge.py,
            // kept in the pending buffer until the bridge acknowledges it.
            pending_add(&mfrc->uid, authorized);

            // Put the card to sleep so it is not reported again until removed
            // and re-presented, and leave the reader in a clean state.
            PICC_HaltA(mfrc);
            PCD_StopCrypto1(mfrc);
            mark_seen(&mfrc->uid);
        }
    }

    return 0;
}
