#include "../include/DES_modes_file.h"
#include "../include/DES_api.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_PLAINTEXT_LEN 100
#define MAX_CIPHERTEXT_LEN 300
#define HEX_STRING_BUFFER_SIZE (MAX_CIPHERTEXT_LEN * 2 + 1)

// כותבת טקסט לקובץ זמני (כעת כותבת בתים)
static void write_bytes_to_temp_file(const uint8_t* data, int len, const char *file_name) {
    FILE* file = fopen(file_name, "wb");
    if (!file) {
        perror("Failed to create temp binary file");
        return;
    }
    fwrite(data, sizeof(uint8_t), len, file);
    fclose(file);
}

// כותבת תוכן בינארי לקובץ (אותה פונקציה)
static void write_binary_to_file(const uint8_t* data, int len, const char* file_name) {
    FILE* file = fopen(file_name, "wb");
    if (!file) {
        perror("Failed to create binary file");
        return;
    }
    fwrite(data, sizeof(uint8_t), len, file);
    fclose(file);
}

// מוחקת קובץ
static void delete_file(const char* filename) {
    if (remove(filename) != 0) {
        perror("Failed to delete file");
    }
}

// קריאת תוכן בינארי מקובץ
static size_t read_file_to_bytes(const char* filename, int max_len, uint8_t* out_bytes) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        perror("Failed to open file for reading (binary)");
        return 0;
    }
    size_t bytesRead = fread(out_bytes, sizeof(uint8_t), max_len, file);
    fclose(file);
    return bytesRead;
}

// קריאת טקסט מקובץ (משמש רק לפענוח סופי)
static size_t read_text_from_file(const char* filename, int max_len, char* out_text) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open file for reading (text)");
        return 0;
    }
    size_t bytesRead = fread(out_text, sizeof(char), max_len, file);
    out_text[bytesRead] = '\0';
    fclose(file);
    return bytesRead;
}

// מחרוזת הקסה -> uint64 (אותה פונקציה)
static uint64_t hex_string_to_uint64(const char *hex_str) {
    if (strlen(hex_str) != 16) {
        fprintf(stderr, "Invalid hex string length (expected 16)\n");
        exit(1);
    }
    uint64_t result = 0;
    for (int i = 0; i < 16; i++) {
        char c = hex_str[i];
        uint8_t value;
        if (c >= '0' && c <= '9') value = c - '0';
        else if (c >= 'a' && c <= 'f') value = 10 + (c - 'a');
        else if (c >= 'A' && c <= 'F') value = 10 + (c - 'A');
        else {
            fprintf(stderr, "Invalid hex character: %c\n", c);
            exit(1);
        }
        result = (result << 4) | value;
    }
    return result;
}

// בתים -> מחרוזת הקסה (אותה פונקציה)
static void bytes_to_hex_string(const uint8_t *bytes, int len, char *hex_str) {
    const char *hex_chars = "0123456789abcdef";
    for (int i = 0; i < len; i++) {
        hex_str[i * 2]     = hex_chars[(bytes[i] >> 4) & 0xF];
        hex_str[i * 2 + 1] = hex_chars[bytes[i] & 0xF];
    }
    hex_str[len * 2] = '\0';
}

// מחרוזת הקסה -> בתים (אותה פונקציה)
static void hex_string_to_bytes(const char* hex_str, uint8_t* bytes, int* num_bytes) {
    int len = strlen(hex_str);
    if (len % 2 != 0) {
        fprintf(stderr, "Hex string must have even length\n");
        exit(1);
    }
    *num_bytes = len / 2;
    for (int i = 0; i < *num_bytes; i++) {
        sscanf(hex_str + 2 * i, "%2hhx", &bytes[i]);
    }
}

// ההפעלה המרכזית - גרסה מעודכנת לטיפול בטקסט
CRYPTO_API int run_DES_operation(
    const char* key,
    int mode, // 0-4
    int isDecrypt, // 1 = decrypt, 0 = encrypt
    int use_text_input, // 1 = text input, 0 = file
    const char* input_file,
    const char* input_text,
    int size_of_input_text,
    char* output_file_name,
    char** output_text,
    int* size_of_output_text,
    //קבצים זמניים שנוצרים בתוך App_Data
    const char* tempIn,
    const char* tempOut
) {
    int (*modes_functions[5][2])(const char *, const char *, uint64_t);
    uint64_t hexKey = hex_string_to_uint64(key);

    int error_code = 0;

    //ECB
    modes_functions[0][0] = encrypt_file_ECB; modes_functions[0][1] = decrypt_file_ECB;

    //CBC
    modes_functions[1][0] = encrypt_file_CBC; modes_functions[1][1] = decrypt_file_CBC;

    //CFB
    modes_functions[2][0] = encrypt_file_CFB; modes_functions[2][1] = decrypt_file_CFB;

    //OFB
    modes_functions[3][0] = encrypt_file_OFB; modes_functions[3][1] = decrypt_file_OFB;

    //CTR
    modes_functions[4][0] = encrypt_file_CTR; modes_functions[4][1] = decrypt_file_CTR;

    if (use_text_input) {
        if (!isDecrypt) {
            // Encrypt
            write_bytes_to_temp_file((const uint8_t*)input_text, size_of_input_text, tempIn);
            error_code = modes_functions[mode][0](tempIn, tempOut, hexKey);

            uint8_t ciphertext_bytes[MAX_CIPHERTEXT_LEN];
            size_t ciphertext_len = read_file_to_bytes(tempOut, MAX_CIPHERTEXT_LEN, ciphertext_bytes);

            *size_of_output_text = ciphertext_len * 2;
            *output_text = malloc(*size_of_output_text + 1);
            bytes_to_hex_string(ciphertext_bytes, ciphertext_len, *output_text);

            delete_file(tempIn);
            delete_file(tempOut);

        } else {
            // Decrypt
            uint8_t ciphertext_bytes[MAX_CIPHERTEXT_LEN];
            int num_bytes;
            hex_string_to_bytes(input_text, ciphertext_bytes, &num_bytes);

            write_bytes_to_temp_file(ciphertext_bytes, num_bytes, tempIn);
            error_code = modes_functions[mode][1](tempIn, tempOut, hexKey);

            char* plaintext = calloc(MAX_PLAINTEXT_LEN + 1, sizeof(char));
            *size_of_output_text = read_text_from_file(tempOut, MAX_PLAINTEXT_LEN, plaintext);
            *output_text = plaintext;

            delete_file(tempIn);
            delete_file(tempOut);
        }
    } else {
        // File mode (ללא שינוי)
        error_code = modes_functions[mode][isDecrypt](input_file, output_file_name, hexKey);
    }
    return error_code;
}

CRYPTO_API void free_output(char* ptr) {
    free(ptr);
}

CRYPTO_API void generate_random_key(char** key) {
    uint8_t keyArr[8];
    uint64_t keyHex = generate_hex_key();
    memcpy(keyArr, &keyHex, 8);
    *key = calloc(17, sizeof(char)); // 8 bytes * 2 chars/byte + null terminator
    if (*key == NULL) return; // טיפול בכישלון הקצאת זיכרון

    bytes_to_hex_string(keyArr, 8, *key);
}