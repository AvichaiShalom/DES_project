#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "../include/constants.h"
#include "../include/DES_block.h"

void add_padding_buffer(uint8_t* input, size_t input_len, uint8_t* output) {
    size_t padding = BLOCK_SIZE_BYTES - input_len;
    memcpy(output, input, input_len);
    for (size_t i = input_len; i < BLOCK_SIZE_BYTES - 1; i++) {
        output[i] = 0;
    }
    output[BLOCK_SIZE_BYTES - 1] = (uint8_t)padding;
}

void remove_padding_buffer(uint8_t* buffer, size_t* output_len) {
    size_t padding = buffer[BLOCK_SIZE_BYTES - 1];
    *output_len = BLOCK_SIZE_BYTES - padding;
}

void encrypt_buffer_ECB(char* buffer, int buffer_length, uint64_t key, char** out_buffer, int* out_buffer_length) {
    int full_blocks = buffer_length / BLOCK_SIZE_BYTES;
    int remainder = buffer_length % BLOCK_SIZE_BYTES;
    int total_blocks = full_blocks + 1; // תמיד נוסיף בלוק עם פדינג
    uint64_t block, ciphertext;
    uint8_t temp[BLOCK_SIZE_BYTES];

    *out_buffer_length = total_blocks * BLOCK_SIZE_BYTES;
    *out_buffer = (char*)malloc(*out_buffer_length);
    if (!*out_buffer) {
        perror("Memory allocation failed");
        exit(1);
    }

    for (int i = 0; i < full_blocks; i++) {
        memcpy(&block, buffer + i * BLOCK_SIZE_BYTES, BLOCK_SIZE_BYTES);
        DES_encrypt(block, &ciphertext, key);
        memcpy(*out_buffer + i * BLOCK_SIZE_BYTES, &ciphertext, BLOCK_SIZE_BYTES);
    }

    // טיפול בפדינג
    add_padding_buffer((uint8_t*)(buffer + full_blocks * BLOCK_SIZE_BYTES), remainder, temp);
    memcpy(&block, temp, BLOCK_SIZE_BYTES);
    DES_encrypt(block, &ciphertext, key);
    memcpy(*out_buffer + full_blocks * BLOCK_SIZE_BYTES, &ciphertext, BLOCK_SIZE_BYTES);
}

void decrypt_buffer_ECB(char* buffer, int buffer_length, uint64_t key, char** out_buffer, int* out_buffer_length) {
    if (buffer_length % BLOCK_SIZE_BYTES != 0) {
        fprintf(stderr, "Invalid ciphertext length\n");
        exit(1);
    }

    int total_blocks = buffer_length / BLOCK_SIZE_BYTES;
    uint64_t ciphertext, decrypted_block;
    uint8_t temp[BLOCK_SIZE_BYTES];
    size_t actual_len;

    *out_buffer = (char*)malloc(buffer_length); // באותו גודל של המוצפן, נחתוך בסוף לפי פדינג
    if (!*out_buffer) {
        perror("Memory allocation failed");
        exit(1);
    }

    for (int i = 0; i < total_blocks - 1; i++) {
        memcpy(&ciphertext, buffer + i * BLOCK_SIZE_BYTES, BLOCK_SIZE_BYTES);
        DES_decrypt(ciphertext, &decrypted_block, key);
        memcpy(*out_buffer + i * BLOCK_SIZE_BYTES, &decrypted_block, BLOCK_SIZE_BYTES);
    }

    // טיפול בבלוק האחרון – כולל הסרת פדינג
    memcpy(&ciphertext, buffer + (total_blocks - 1) * BLOCK_SIZE_BYTES, BLOCK_SIZE_BYTES);
    DES_decrypt(ciphertext, &decrypted_block, key);
    memcpy(temp, &decrypted_block, BLOCK_SIZE_BYTES);
    remove_padding_buffer(temp, &actual_len);
    memcpy(*out_buffer + (total_blocks - 1) * BLOCK_SIZE_BYTES, temp, actual_len);

    *out_buffer_length = (total_blocks - 1) * BLOCK_SIZE_BYTES + actual_len;
}

void encrypt_buffer_CBC(char* buffer, int buffer_length, uint64_t key, char** out_buffer, int* out_buffer_length) {
    int full_blocks = buffer_length / BLOCK_SIZE_BYTES;
    int remainder = buffer_length % BLOCK_SIZE_BYTES;
    int total_blocks = full_blocks + 1; // תמיד נוסיף בלוק עם פדינג
    uint64_t block, ciphertext;
    uint8_t temp[BLOCK_SIZE_BYTES];
    uint8_t iv[BLOCK_SIZE_BYTES];

    // הקצאת זיכרון: בלוק אחד נוסף עבור ה-IV
    *out_buffer_length = (total_blocks + 1) * BLOCK_SIZE_BYTES;
    *out_buffer = (char*)malloc(*out_buffer_length);
    if (!*out_buffer) {
        perror("Memory allocation failed");
        exit(1);
    }

    // יצירת IV רנדומלי ושמירה בתחילת הפלט
    srand(time(NULL));
    for (int i = 0; i < BLOCK_SIZE_BYTES; i++) {
        iv[i] = rand() % 256;
    }
    memcpy(*out_buffer, iv, BLOCK_SIZE_BYTES);
    memcpy(&ciphertext, iv, BLOCK_SIZE_BYTES); // ciphertext acts as previous block (starts with IV)

    // הצפנת בלוקים מלאים
    for (int i = 0; i < full_blocks; i++) {
        memcpy(&block, buffer + i * BLOCK_SIZE_BYTES, BLOCK_SIZE_BYTES);
        block ^= ciphertext;
        DES_encrypt(block, &ciphertext, key);
        memcpy(*out_buffer + (i + 1) * BLOCK_SIZE_BYTES, &ciphertext, BLOCK_SIZE_BYTES);
    }

    // בלוק אחרון עם פדינג
    add_padding_buffer((uint8_t*)(buffer + full_blocks * BLOCK_SIZE_BYTES), remainder, temp);
    memcpy(&block, temp, BLOCK_SIZE_BYTES);
    block ^= ciphertext;
    DES_encrypt(block, &ciphertext, key);
    memcpy(*out_buffer + (full_blocks + 1) * BLOCK_SIZE_BYTES - BLOCK_SIZE_BYTES, &ciphertext, BLOCK_SIZE_BYTES);
}

void decrypt_buffer_CBC(char* buffer, int buffer_length, uint64_t key, char** out_buffer, int* out_buffer_length) {
    if (buffer_length < 2 * BLOCK_SIZE_BYTES || buffer_length % BLOCK_SIZE_BYTES != 0) {
        fprintf(stderr, "Invalid ciphertext length\n");
        exit(1);
    }

    int total_blocks = buffer_length / BLOCK_SIZE_BYTES;
    uint64_t ciphertext, decrypted_block;
    uint64_t iv;
    uint8_t temp[BLOCK_SIZE_BYTES];
    size_t actual_len;

    *out_buffer = (char*)malloc(buffer_length); // נחתוך את האורך הסופי לאחר ההסרה של הפדינג
    if (!*out_buffer) {
        perror("Memory allocation failed");
        exit(1);
    }

    // קריאת IV
    memcpy(&iv, buffer, BLOCK_SIZE_BYTES);

    for (int i = 1; i < total_blocks - 1; i++) {
        memcpy(&ciphertext, buffer + i * BLOCK_SIZE_BYTES, BLOCK_SIZE_BYTES);
        DES_decrypt(ciphertext, &decrypted_block, key);
        decrypted_block ^= iv;
        memcpy(*out_buffer + (i - 1) * BLOCK_SIZE_BYTES, &decrypted_block, BLOCK_SIZE_BYTES);
        iv = ciphertext;
    }

    // טיפול בבלוק האחרון עם הסרת פדינג
    memcpy(&ciphertext, buffer + (total_blocks - 1) * BLOCK_SIZE_BYTES, BLOCK_SIZE_BYTES);
    DES_decrypt(ciphertext, &decrypted_block, key);
    decrypted_block ^= iv;
    memcpy(temp, &decrypted_block, BLOCK_SIZE_BYTES);
    remove_padding_buffer(temp, &actual_len);
    memcpy(*out_buffer + (total_blocks - 2) * BLOCK_SIZE_BYTES, temp, actual_len);

    *out_buffer_length = (total_blocks - 2) * BLOCK_SIZE_BYTES + actual_len;
}

void encrypt_buffer_CFB(char* buffer, int buffer_length, uint64_t key, char** out_buffer, int* out_buffer_length) {
    int full_blocks = buffer_length / BLOCK_SIZE_BYTES;
    int remainder = buffer_length % BLOCK_SIZE_BYTES;
    int total_blocks = full_blocks + 1; // תמיד נוסיף בלוק אחרון עם פדינג
    uint64_t block, ciphertext;
    uint8_t temp[BLOCK_SIZE_BYTES];
    uint8_t iv[BLOCK_SIZE_BYTES];

    *out_buffer_length = (total_blocks + 1) * BLOCK_SIZE_BYTES; // בלוק נוסף ל-IV
    *out_buffer = (char*)malloc(*out_buffer_length);
    if (!*out_buffer) {
        perror("Memory allocation failed");
        exit(1);
    }

    srand(time(NULL));
    for (int i = 0; i < BLOCK_SIZE_BYTES; i++) {
        iv[i] = rand() % 256;
    }
    memcpy(*out_buffer, iv, BLOCK_SIZE_BYTES); // כתיבה של ה-IV
    memcpy(&block, iv, BLOCK_SIZE_BYTES);      // block = IV

    for (int i = 0; i < full_blocks; i++) {
        DES_encrypt(block, &ciphertext, key);
        memcpy(&block, buffer + i * BLOCK_SIZE_BYTES, BLOCK_SIZE_BYTES); // block = plain
        block ^= ciphertext;
        memcpy(*out_buffer + (i + 1) * BLOCK_SIZE_BYTES, &block, BLOCK_SIZE_BYTES); // כתיבה של ciphertext
    }

    // בלוק אחרון עם פדינג
    DES_encrypt(block, &ciphertext, key);
    add_padding_buffer((uint8_t*)(buffer + full_blocks * BLOCK_SIZE_BYTES), remainder, temp);
    memcpy(&block, temp, BLOCK_SIZE_BYTES);
    block ^= ciphertext;
    memcpy(*out_buffer + (full_blocks + 1) * BLOCK_SIZE_BYTES - BLOCK_SIZE_BYTES, &block, BLOCK_SIZE_BYTES);
}

void decrypt_buffer_CFB(char* buffer, int buffer_length, uint64_t key, char** out_buffer, int* out_buffer_length) {
    if (buffer_length < 2 * BLOCK_SIZE_BYTES || buffer_length % BLOCK_SIZE_BYTES != 0) {
        fprintf(stderr, "Invalid ciphertext length\n");
        exit(1);
    }

    int total_blocks = buffer_length / BLOCK_SIZE_BYTES;
    uint64_t ciphertext, decrypted_block;
    uint64_t last_block;
    uint8_t temp[BLOCK_SIZE_BYTES];
    size_t actual_len;

    *out_buffer = (char*)malloc(buffer_length);
    if (!*out_buffer) {
        perror("Memory allocation failed");
        exit(1);
    }

    memcpy(&last_block, buffer, BLOCK_SIZE_BYTES); // קריאת ה-IV

    for (int i = 1; i < total_blocks - 1; i++) {
        memcpy(&ciphertext, buffer + i * BLOCK_SIZE_BYTES, BLOCK_SIZE_BYTES);
        DES_encrypt(last_block, &decrypted_block, key);
        decrypted_block ^= ciphertext;
        memcpy(*out_buffer + (i - 1) * BLOCK_SIZE_BYTES, &decrypted_block, BLOCK_SIZE_BYTES);
        last_block = ciphertext;
    }

    // טיפול בבלוק האחרון
    memcpy(&ciphertext, buffer + (total_blocks - 1) * BLOCK_SIZE_BYTES, BLOCK_SIZE_BYTES);
    DES_encrypt(last_block, &decrypted_block, key);
    decrypted_block ^= ciphertext;
    memcpy(temp, &decrypted_block, BLOCK_SIZE_BYTES);
    remove_padding_buffer(temp, &actual_len);
    memcpy(*out_buffer + (total_blocks - 2) * BLOCK_SIZE_BYTES, temp, actual_len);

    *out_buffer_length = (total_blocks - 2) * BLOCK_SIZE_BYTES + actual_len;
}

void encrypt_buffer_OFB(char* buffer, int buffer_length, uint64_t key, char** out_buffer, int* out_buffer_length) {
    int full_blocks = buffer_length / BLOCK_SIZE_BYTES;
    int remainder = buffer_length % BLOCK_SIZE_BYTES;
    int total_blocks = full_blocks + 1;
    uint64_t block, iv, encIV;
    uint8_t temp[BLOCK_SIZE_BYTES];
    uint8_t iv_raw[BLOCK_SIZE_BYTES];

    *out_buffer_length = (total_blocks + 1) * BLOCK_SIZE_BYTES; // כולל IV
    *out_buffer = (char*)malloc(*out_buffer_length);
    if (!*out_buffer) {
        perror("Memory allocation failed");
        exit(1);
    }

    srand(time(NULL));
    for (int i = 0; i < BLOCK_SIZE_BYTES; i++) {
        iv_raw[i] = rand() % 256;
    }
    memcpy(*out_buffer, iv_raw, BLOCK_SIZE_BYTES);
    memcpy(&iv, iv_raw, BLOCK_SIZE_BYTES);

    for (int i = 0; i < full_blocks; i++) {
        DES_encrypt(iv, &encIV, key);
        iv = encIV;
        memcpy(&block, buffer + i * BLOCK_SIZE_BYTES, BLOCK_SIZE_BYTES);
        block ^= encIV;
        memcpy(*out_buffer + (i + 1) * BLOCK_SIZE_BYTES, &block, BLOCK_SIZE_BYTES);
    }

    // בלוק אחרון עם פדינג
    DES_encrypt(iv, &encIV, key);
    add_padding_buffer((uint8_t*)(buffer + full_blocks * BLOCK_SIZE_BYTES), remainder, temp);
    memcpy(&block, temp, BLOCK_SIZE_BYTES);
    block ^= encIV;
    memcpy(*out_buffer + (full_blocks + 1) * BLOCK_SIZE_BYTES - BLOCK_SIZE_BYTES, &block, BLOCK_SIZE_BYTES);
}

void decrypt_buffer_OFB(char* buffer, int buffer_length, uint64_t key, char** out_buffer, int* out_buffer_length) {
    if (buffer_length < 2 * BLOCK_SIZE_BYTES || buffer_length % BLOCK_SIZE_BYTES != 0) {
        fprintf(stderr, "Invalid ciphertext length\n");
        exit(1);
    }

    int total_blocks = buffer_length / BLOCK_SIZE_BYTES;
    uint64_t ciphertext, plaintext, iv, encIV;
    uint8_t temp[BLOCK_SIZE_BYTES];
    size_t actual_len;

    *out_buffer = (char*)malloc(buffer_length);
    if (!*out_buffer) {
        perror("Memory allocation failed");
        exit(1);
    }

    memcpy(&iv, buffer, BLOCK_SIZE_BYTES);

    for (int i = 1; i < total_blocks - 1; i++) {
        memcpy(&ciphertext, buffer + i * BLOCK_SIZE_BYTES, BLOCK_SIZE_BYTES);
        DES_encrypt(iv, &encIV, key);
        iv = encIV;
        plaintext = ciphertext ^ encIV;
        memcpy(*out_buffer + (i - 1) * BLOCK_SIZE_BYTES, &plaintext, BLOCK_SIZE_BYTES);
    }

    // בלוק אחרון עם פדינג
    memcpy(&ciphertext, buffer + (total_blocks - 1) * BLOCK_SIZE_BYTES, BLOCK_SIZE_BYTES);
    DES_encrypt(iv, &encIV, key);
    plaintext = ciphertext ^ encIV;
    memcpy(temp, &plaintext, BLOCK_SIZE_BYTES);
    remove_padding_buffer(temp, &actual_len);
    memcpy(*out_buffer + (total_blocks - 2) * BLOCK_SIZE_BYTES, temp, actual_len);

    *out_buffer_length = (total_blocks - 2) * BLOCK_SIZE_BYTES + actual_len;
}

void encrypt_buffer_CTR(char* buffer, int buffer_length, uint64_t key, char** out_buffer, int* out_buffer_length) {
    int full_blocks = buffer_length / BLOCK_SIZE_BYTES;
    int remainder = buffer_length % BLOCK_SIZE_BYTES;
    int total_blocks = full_blocks + 1;
    uint64_t block, encCTR;
    uint8_t temp[BLOCK_SIZE_BYTES];
    char nonceArr[INT_4_BYTES];
    uint32_t nonce, counter = 0;

    *out_buffer_length = (total_blocks * BLOCK_SIZE_BYTES) + INT_4_BYTES;
    *out_buffer = (char*)malloc(*out_buffer_length);
    if (!*out_buffer) {
        perror("Memory allocation failed");
        exit(1);
    }

    // יצירת nonce ושמירתו בתחילת הפלט
    srand(time(NULL));
    for (int i = 0; i < INT_4_BYTES; i++) {
        nonceArr[i] = rand() % 256;
    }
    memcpy(&nonce, nonceArr, INT_4_BYTES);
    memcpy(*out_buffer, &nonce, INT_4_BYTES);

    for (int i = 0; i < full_blocks; i++) {
        DES_encrypt(((uint64_t)nonce << INT_32_BITS) | counter, &encCTR, key);
        memcpy(&block, buffer + i * BLOCK_SIZE_BYTES, BLOCK_SIZE_BYTES);
        block ^= encCTR;
        memcpy(*out_buffer + INT_4_BYTES + i * BLOCK_SIZE_BYTES, &block, BLOCK_SIZE_BYTES);
        counter++;
    }

    // בלוק אחרון עם פדינג
    DES_encrypt(((uint64_t)nonce << INT_32_BITS) | counter, &encCTR, key);
    add_padding_buffer((uint8_t*)(buffer + full_blocks * BLOCK_SIZE_BYTES), remainder, temp);
    memcpy(&block, temp, BLOCK_SIZE_BYTES);
    block ^= encCTR;
    memcpy(*out_buffer + INT_4_BYTES + full_blocks * BLOCK_SIZE_BYTES, &block, BLOCK_SIZE_BYTES);
}

void decrypt_buffer_CTR(char* buffer, int buffer_length, uint64_t key, char** out_buffer, int* out_buffer_length) {
    if (buffer_length < INT_4_BYTES + BLOCK_SIZE_BYTES || (buffer_length - INT_4_BYTES) % BLOCK_SIZE_BYTES != 0) {
        fprintf(stderr, "Invalid ciphertext length\n");
        exit(1);
    }

    int total_blocks = (buffer_length - INT_4_BYTES) / BLOCK_SIZE_BYTES;
    uint64_t block, encCTR;
    uint32_t nonce, counter = 0;
    uint8_t temp[BLOCK_SIZE_BYTES];
    size_t actual_len;

    *out_buffer = (char*)malloc(buffer_length); // ייחתך לאחר הסרת הפאדינג
    if (!*out_buffer) {
        perror("Memory allocation failed");
        exit(1);
    }

    memcpy(&nonce, buffer, INT_4_BYTES);

    for (int i = 0; i < total_blocks - 1; i++) {
        memcpy(&block, buffer + INT_4_BYTES + i * BLOCK_SIZE_BYTES, BLOCK_SIZE_BYTES);
        DES_encrypt(((uint64_t)nonce << INT_32_BITS) | counter, &encCTR, key);
        block ^= encCTR;
        memcpy(*out_buffer + i * BLOCK_SIZE_BYTES, &block, BLOCK_SIZE_BYTES);
        counter++;
    }

    // בלוק אחרון עם הסרת פדינג
    memcpy(&block, buffer + INT_4_BYTES + (total_blocks - 1) * BLOCK_SIZE_BYTES, BLOCK_SIZE_BYTES);
    DES_encrypt(((uint64_t)nonce << INT_32_BITS) | counter, &encCTR, key);
    block ^= encCTR;
    memcpy(temp, &block, BLOCK_SIZE_BYTES);
    remove_padding_buffer(temp, &actual_len);
    memcpy(*out_buffer + (total_blocks - 1) * BLOCK_SIZE_BYTES, temp, actual_len);

    *out_buffer_length = (total_blocks - 1) * BLOCK_SIZE_BYTES + actual_len;
}
