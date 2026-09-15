#include <stdio.h>
#include <stdbool.h>
#include "pico/stdlib.h"
#include "hardware/spi.h"
#include "mfrc522.h"

#define SPI_PORT spi0
#define PIN_MISO 16
#define PIN_CS   17
#define PIN_SCK  18
#define PIN_MOSI 19
#define RESET_PIN 15

const uint8_t AUTHORIZED_UID[] = {0xDE, 0xAD, 0xBE, 0xEF};
const uint8_t UID_LENGTH = 4;

int main() {
    stdio_init_all();
    sleep_ms(2000);

    printf("Initializing SPI...\n");
    spi_init(SPI_PORT, 500 * 1000);
    gpio_set_function(PIN_MISO, GPIO_FUNC_SPI);
    gpio_set_function(PIN_SCK, GPIO_FUNC_SPI);
    gpio_set_function(PIN_MOSI, GPIO_FUNC_SPI);

    gpio_init(PIN_CS);
    gpio_set_dir(PIN_CS, GPIO_OUT);
    gpio_put(PIN_CS, 1);

    gpio_init(RESET_PIN);
    gpio_set_dir(RESET_PIN, GPIO_OUT);
    gpio_put(RESET_PIN, 1);

    MFRC522Ptr_t mfrc = MFRC522_Init();
    PCD_Init(mfrc, SPI_PORT);

    printf("Checking RC522 communication...\n");
    PCD_DumpVersionToSerial(mfrc);

    int counter = 0;

    while (1) {
        sleep_ms(500);

        if (counter >= 10) {
            gpio_put(RESET_PIN, 0);
            sleep_ms(50);
            gpio_put(RESET_PIN, 1);
            sleep_ms(50);

            PCD_Init(mfrc, SPI_PORT);
            counter = 0;
        }

        counter++;

        if (PICC_IsNewCardPresent(mfrc)) {
            if (PICC_ReadCardSerial(mfrc)) {
                printf("Card UID: ");

                bool is_authorized = true;

                for (int i = 0; i < mfrc->uid.size; i++) {
                    printf("%02X ", mfrc->uid.uidByte[i]);

                    if (mfrc->uid.size == UID_LENGTH) {
                        if (mfrc->uid.uidByte[i] != AUTHORIZED_UID[i]) {
                            is_authorized = false;
                        }
                    } else {
                        is_authorized = false;
                    }
                }

                printf("\n");

                if (is_authorized) {
                    printf(">>> AUTHORIZED: Bicycle Unlocked!\n");
                } else {
                    printf(">>> DENIED: Unauthorized Tag.\n");
                }

                PICC_HaltA(mfrc);
                PCD_StopCrypto1(mfrc);

                counter = 0;
            } else {
                printf("Card present but UID read failed\n");
                PCD_StopCrypto1(mfrc);
            }
        }
    }

    return 0;
}
