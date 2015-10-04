
/**
* This example shows how to configure GPIO pins as outputs which can also be used to drive LEDs.
* Each LED is set on one at a time and each state lasts 100 milliseconds.
*/

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "hexdump.h"

#include "aes.h"

extern void initialise_monitor_handles(void);

/**
 * \brief dumps the contents of a buffer to the console
 */
void hexdump_block(const void* data, size_t length, uint8_t indent, uint8_t width){
    uint16_t i;
    uint8_t  j;
    for (i = 0; i < length; ++i){
        if (i % width == 0){
            putchar('\n');
            for(j = 0; j < indent; ++j){
                putchar(' ');
            }
        }
        printf("%02x ", *((uint8_t*)data));
        data = (uint8_t*)data +1;
    }
}

void aes_test(void) {
/*    uint8_t key[16] = { 0, 1, 2 , 3, 4, 5, 6, 7,
                        8, 9, 10, 11, 12, 13, 14, 15 };
    uint8_t plain[16] = {
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    */
    uint8_t key[16] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    uint8_t plain[16] = {
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
            0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
    };
    uint8_t cipher[16];
    aes128_ctx_t ctx;
    DUMP(key);
    DUMP(plain);
    aes128_init(key, &ctx);
    memcpy(cipher, plain, sizeof(cipher));
    aes128_enc(cipher, &ctx);
    DUMP(cipher);
    memcpy(plain, cipher, sizeof(plain));
    aes128_dec(plain, &ctx);
    DUMP(plain);
}

int main()
{

//    initialise_monitor_handles();

    printf("hello world!\n");
    aes_test();
    _Exit(EXIT_SUCCESS);
    for (;;)
        ;

    return 0;
}
