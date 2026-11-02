#include <stdio.h>
#include <stdbool.h>
#include "pico/stdlib.h"
#include "hardware/spi.h"
#include "mfrc522.h"

/* ---------------------------------------------------------------------------
 * Wiring: this is the ONLY place pins are defined. Change them here to match
 * the physical connections between the Pico 2 W and the RC522 module.
 *
 *   RC522 pin   Pico GPIO
 *   SDA (NSS)   PIN_CS
  *   MISO        PIN_MISO
 *   RST         PIN_RST
 *   3.3V        3V3 (NOT 5V)
 *   GND         GND
 *   SCK         PIN_SCK
 *   MOSI        PIN_MOSI

 *
 * SCK/MOSI/MISO must be a valid pin set for the chosen SPI_PORT
 * (spi0: SCK 2/6/18, MOSI 3/7/19, MISO 4/16/20).
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

// How often to poll for a card, and how often to verify the reader is alive.
#define POLL_INTERVAL_MS      50
#define HEALTH_CHECK_MS       1000
// How long a card is ignored after a successful read while it stays on the
// reader (a halted card does not answer REQA anyway; this covers cards that
// fail to halt).
#define REREAD_HOLDOFF_MS     1500
// Heartbeat interval. The dashboard marks a reader offline when it stops
// hearing these (see dashboard/server.py OFFLINE_AFTER_S).
#define HEARTBEAT_MS          30000

// Identifier of this reader station. Each physical reader is bolted to a known
// bike rack; the dashboard maps this ID to a campus location (dashboard/readers.json).
#define READER_ID "rack-01"

static const uint8_t AUTHORIZED_UID[] = {0xDE, 0xAD, 0xBE, 0xEF};
#define AUTHORIZED_UID_LEN (sizeof(AUTHORIZED_UID) / sizeof(AUTHORIZED_UID[0]))

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

    MFRC522Ptr_t mfrc = MFRC522_Init(SPI_PORT, PIN_CS, PIN_RST);
    if (mfrc == NULL) {
        printf("FATAL: could not allocate MFRC522 instance\n");
        while (true) tight_loop_contents();
    }

    init_reader_blocking(mfrc);
#ifdef RFID_DIAG
    diag_run(mfrc);
    PCD_Init(mfrc);
#endif
    printf("Waiting for cards...\n");

    absolute_time_t next_health_check = make_timeout_time_ms(HEALTH_CHECK_MS);
    absolute_time_t next_heartbeat = get_absolute_time();
    absolute_time_t reread_allowed_at = get_absolute_time();
    uint32_t consecutive_failures = 0;
    uint32_t recoveries = 0;

    while (true) {
        sleep_ms(POLL_INTERVAL_MS);

        // Machine-readable liveness line for dashboard/serial_bridge.py:
        //   HB,<reader_id>
        if (time_reached(next_heartbeat)) {
            next_heartbeat = make_timeout_time_ms(HEARTBEAT_MS);
            printf("HB,%s\n", READER_ID);
        }

        // Confirm the chip still has our configuration. A cheap one-register
        // check runs on every poll (a chip reset clears the antenna-enable
        // bits, and we measured rare resets under the antenna's current step);
        // the full check runs once a second. Re-init only when the config is
        // actually gone, so the reader is never blinded by a blind timer reset.
        bool full_check = time_reached(next_health_check);
        if (full_check) next_health_check = make_timeout_time_ms(HEALTH_CHECK_MS);
        if ((PCD_ReadRegister(mfrc, TxControlReg) & 0x03) != 0x03 || (full_check && !PCD_IsHealthy(mfrc))) {
            recoveries++;
            printf("RC522 lost its configuration (recovery #%lu), re-initializing...\n", (unsigned long)recoveries);
            init_reader_blocking(mfrc);
            consecutive_failures = 0;
            continue;
        }

        if (!PICC_IsNewCardPresent(mfrc)) {
            continue;
        }

        if (!time_reached(reread_allowed_at)) {
            // Same card still sitting on the reader; don't spam the log.
            continue;
        }

        if (!PICC_ReadCardSerial(mfrc)) {
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
            continue;
        }

        consecutive_failures = 0;
        print_uid(&mfrc->uid);

        bool authorized = uid_is_authorized(&mfrc->uid);
        if (authorized) {
            printf(">>> AUTHORIZED: Bicycle Unlocked!\n");
        } else {
            printf(">>> DENIED: Unauthorized Tag.\n");
        }

        // Machine-readable log line consumed by dashboard/serial_bridge.py:
        //   SCAN,<reader_id>,<uid hex without spaces>,<1 if authorized else 0>
        printf("SCAN,%s,", READER_ID);
        for (uint8_t i = 0; i < mfrc->uid.size; i++) {
            printf("%02X", mfrc->uid.uidByte[i]);
        }
        printf(",%d\n", authorized ? 1 : 0);

        // Put the card to sleep so it is not reported again until removed
        // and re-presented, and leave the reader in a clean state.
        PICC_HaltA(mfrc);
        PCD_StopCrypto1(mfrc);
        reread_allowed_at = make_timeout_time_ms(REREAD_HOLDOFF_MS);
    }

    return 0;
}
