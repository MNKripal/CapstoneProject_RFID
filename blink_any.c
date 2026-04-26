#include <stdio.h>
#include "pico/stdlib.h"
#include "hardware/spi.h"
#include "mfrc522.h"

#define RESET_PIN 15   // already defined, keep same

int main() {
    stdio_init_all();
    sleep_ms(5000);

    // Setup RESET pin
    gpio_init(RESET_PIN);
    gpio_set_dir(RESET_PIN, GPIO_OUT);
    gpio_put(RESET_PIN, 1);

    MFRC522Ptr_t mfrc = MFRC522_Init();
    PCD_Init(mfrc, spi0);

    printf("Checking RC522 communication...\n");
    PCD_DumpVersionToSerial(mfrc);

    int counter = 0;

    while (1) {
        sleep_ms(500);
        printf("Polling...\n");

        // 🔥 Reset every ~5 seconds (10 loops * 500ms)
        if (counter >= 10) {
            printf("Hardware resetting RC522...\n");

            gpio_put(RESET_PIN, 0);
            sleep_ms(100);
            gpio_put(RESET_PIN, 1);
            sleep_ms(50);

            // Re-init after reset
            PCD_Init(mfrc, spi0);

            counter = 0;
        }

        counter++;

        if (PICC_IsNewCardPresent(mfrc)) {
            printf("Card detected at presence stage\n");

            if (PICC_ReadCardSerial(mfrc)) {
                printf("Card UID: ");

                for (int i = 0; i < mfrc->uid.size; i++) {
                    printf("%02X ", mfrc->uid.uidByte[i]);
                }

                printf("\n");

                PICC_HaltA(mfrc);
                PCD_StopCrypto1(mfrc);
            } else {
                printf("Card present but UID read failed\n");
                PCD_StopCrypto1(mfrc);
            }
        }
    }

    return 0;
}