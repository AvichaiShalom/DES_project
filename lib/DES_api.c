#include "../include/DES_modes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_PLAINTEXT_LEN 100
#define MAX_CIPHERTEXT_LEN 300
#define TEMP_FILENAME_IN "temp_input.txt"
#define TEMP_FILENAME_OUT "temp_output.txt"

// כותבת טקסט לקובץ זמני
void write_text_to_temp_file(const char *text, const char *file_name) {
    FILE* file = fopen(file_name, "w");
    if (!file) {
        perror("Failed to create temp file");
        return;
    }

    fprintf(file, "%s", text);
    fclose(file);
}

// כותבת תוכן בינארי לקובץ
void write_bytes_to_file(const uint8_t* data, int len, const char* file_name) {
    FILE* file = fopen(file_name, "wb");
    if (!file) {
        perror("Failed to create binary file");
        return;
    }

    fwrite(data, sizeof(uint8_t), len, file);
    fclose(file);
}

// מוחקת קובץ
void delete_file(const char* filename) {
    if (remove(filename) != 0) {
        perror("Failed to delete file");
    }
}

// קריאת טקסט מקובץ
size_t read_file_to_text(const char* filename, int max_len, char* out_text) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open file for reading");
        return 0;
    }

    size_t bytesRead = fread(out_text, sizeof(char), max_len, file);
    out_text[bytesRead] = '\0';
    fclose(file);
    return bytesRead;
}

// קריאת תוכן בינארי מקובץ
size_t read_file_to_bytes(const char* filename, int max_len, uint8_t* out_bytes) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        perror("Failed to open file for reading binary");
        return 0;
    }

    size_t bytesRead = fread(out_bytes, sizeof(uint8_t), max_len, file);
    fclose(file);
    return bytesRead;
}

// מחרוזת הקסה -> uint64
uint64_t hex_string_to_uint64(const char *hex_str) {
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

// בתים -> מחרוזת הקסה
void bytes_to_hex_string(const uint8_t *bytes, int len, char *hex_str) {
    const char *hex_chars = "0123456789abcdef";
    for (int i = 0; i < len; i++) {
        hex_str[i * 2]     = hex_chars[(bytes[i] >> 4) & 0xF];
        hex_str[i * 2 + 1] = hex_chars[bytes[i] & 0xF];
    }
    hex_str[len * 2] = '\0';
}

// מחרוזת הקסה -> בתים
void hex_string_to_bytes(const char* hex_str, uint8_t* bytes, int* num_bytes) {
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

// הצפנה/פענוח של טקסט, מחזיר טקסט מוצפן או מפוענח
char *encrypt_decrypt_text(
    const char *input_text,
    void (*mode_function)(const char *, const char *, uint64_t),
    uint64_t key,
    int isDecrypt,
    int *length
) {
    char *out = NULL;
    int max_out_len = (!isDecrypt) ? MAX_CIPHERTEXT_LEN : MAX_PLAINTEXT_LEN;

    if (!(out = calloc(max_out_len + 1, sizeof(char)))) {
        perror("could not encrypt/decrypt text");
        exit(1);
    }

    write_text_to_temp_file(input_text, TEMP_FILENAME_IN);
    mode_function(TEMP_FILENAME_IN, TEMP_FILENAME_OUT, key);

    *length = read_file_to_text(TEMP_FILENAME_OUT, max_out_len, out);

    delete_file(TEMP_FILENAME_IN);
    delete_file(TEMP_FILENAME_OUT);

    return out;
}

// ההפעלה המרכזית
__declspec(dllexport) void run_DES_operation(
    const char* key,
    int mode, // 0-4
    int isDecrypt, // 1 = decrypt, 0 = encrypt
    int use_text_input, // 1 = text input, 0 = file
    const char* input_file,
    const char* input_text,
    int size_of_input_text,
    char* output_file_name,
    char** output_text,
    int* size_of_output_text
) {
    void (*modes_functions[5][2])(const char *, const char *, uint64_t);
    uint64_t hexKey = hex_string_to_uint64(key);
    
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
            char* raw_output = encrypt_decrypt_text(input_text, modes_functions[mode][0], hexKey, 0, size_of_output_text);
            uint8_t *output_bytes = (uint8_t *)raw_output;
            int len = *size_of_output_text;

            *output_text = malloc(len * 2 + 1);
            bytes_to_hex_string(output_bytes, len, *output_text);

            free(raw_output);
        } else {
            // Decrypt
            uint8_t input_bytes[MAX_CIPHERTEXT_LEN];
            int num_bytes;
            hex_string_to_bytes(input_text, input_bytes, &num_bytes);

            write_bytes_to_file(input_bytes, num_bytes, TEMP_FILENAME_IN);
            modes_functions[mode][1](TEMP_FILENAME_IN, TEMP_FILENAME_OUT, hexKey);

            char* decrypted = calloc(MAX_PLAINTEXT_LEN + 1, sizeof(char));
            *size_of_output_text = read_file_to_text(TEMP_FILENAME_OUT, MAX_PLAINTEXT_LEN, decrypted);

            *output_text = decrypted;

            delete_file(TEMP_FILENAME_IN);
            delete_file(TEMP_FILENAME_OUT);
        }
    } else {
        // File mode
        modes_functions[mode][isDecrypt](input_file, output_file_name, hexKey);
    }
}
