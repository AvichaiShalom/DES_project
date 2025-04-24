#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void generate_hex_key(uint8_t keyArr[8]) {
    int i = 0;
    srand(time(NULL));
    for (i = 0; i < 8; i++) {
        keyArr[i] = rand() % 256;
    }
}