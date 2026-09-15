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
 *   SCK         PIN_SCK
 *   MOSI        PIN_MOSI
 *   MISO        PIN_MISO
 *   RST         PIN_RST
 *   3.3V        3V3 (NOT 5V)
 *   GND         GND
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
    printf("Waiting for cards...\n");

    absolute_time_t next_health_check = make_timeout_time_ms(HEALTH_CHECK_MS);
    absolute_time_t reread_allowed_at = get_absolute_time();
    uint32_t consecutive_failures = 0;

    while (true) {
        sleep_ms(POLL_INTERVAL_MS);

        // Periodically confirm the chip still has our configuration. Only
        // re-init when it has actually been lost, instead of blindly resetting
        // on a timer (which used to blind the reader for >1 s every 5 s).
        if (time_reached(next_health_check)) {
            next_health_check = make_timeout_time_ms(HEALTH_CHECK_MS);
            if (!PCD_IsHealthy(mfrc)) {
                printf("RC522 lost its configuration, re-initializing...\n");
                init_reader_blocking(mfrc);
                consecutive_failures = 0;
                continue;
            }
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

        if (uid_is_authorized(&mfrc->uid)) {
            printf(">>> AUTHORIZED: Bicycle Unlocked!\n");
        } else {
            printf(">>> DENIED: Unauthorized Tag.\n");
        }

        // Put the card to sleep so it is not reported again until removed
        // and re-presented, and leave the reader in a clean state.
        PICC_HaltA(mfrc);
        PCD_StopCrypto1(mfrc);
        reread_allowed_at = make_timeout_time_ms(REREAD_HOLDOFF_MS);
    }

    return 0;
}
