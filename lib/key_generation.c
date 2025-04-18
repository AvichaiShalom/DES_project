#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

uint64_t generate_hex_key() {
    uint64_t key;
    uint8_t keyArr[8];
    int i = 0;
    srand(time(NULL));
    for (i = 0; i < 8; i++) {
        keyArr[i] = rand() % 256;
    }
    memcpy(&key, keyArr, 8);
    return key;
}