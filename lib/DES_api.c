#include "../include/DES_modes_file.h"
#include "../include/DES_api.h"
#include "../include/key_generation.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#define MAX_PLAINTEXT_LEN 1024 // הגדל גודל מאגר לבטיחות
#define MAX_CIPHERTEXT_LEN (MAX_PLAINTEXT_LEN * 2 + 100) // הגדל גודל מאגר לבטיחות ופלט הקסה
#define TEMP_FILENAME_IN "../temp_input.bin" // שינוי סיומת
#define TEMP_FILENAME_OUT "../temp_output.bin" // שינוי סיומת
#define HEX_STRING_BUFFER_SIZE (MAX_CIPHERTEXT_LEN * 2 + 1)

static int write_bytes_to_temp_file(const uint8_t* data, int len, const char *file_name) {
    FILE* file = fopen(file_name, "wb");
    if (!file) {
        perror("Failed to create temp binary file");
        return -1;
    }
    fwrite(data, sizeof(uint8_t), len, file);
    fclose(file);
    return 0;
}

static int write_binary_to_file(const uint8_t* data, int len, const char* file_name) {
    FILE* file = fopen(file_name, "wb");
    if (!file) {
        perror("Failed to create binary file");
        return -1;
    }
    fwrite(data, sizeof(uint8_t), len, file);
    fclose(file);
    return 0;
}

static void delete_file(const char* filename) {
    remove(filename);
}

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

static size_t read_text_from_file(const char* filename, int max_len, char* out_text) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open file for reading (text)");
        return 0;
    }
    size_t bytesRead = fread(out_text, sizeof(char), max_len -1, file); // השאר מקום לתו Null
    out_text[bytesRead] = '\0';
    fclose(file);
    return bytesRead;
}

static uint64_t hex_string_to_uint64(const char *hex_str, int *error_flag) {
    if (strlen(hex_str) != 16) {
        if (error_flag) *error_flag = 1;
        return 0;
    }
    uint64_t result = 0;
    for (int i = 0; i < 16; i++) {
        char c = hex_str[i];
        uint8_t value;
        if (c >= '0' && c <= '9') value = c - '0';
        else if (c >= 'a' && c <= 'f') value = 10 + (c - 'a');
        else if (c >= 'A' && c <= 'F') value = 10 + (c - 'A');
        else {
            if (error_flag) *error_flag = 2;
            return 0;
        }
        result = (result << 4) | value;
    }
    if (error_flag) *error_flag = 0;
    return result;
}

static void bytes_to_hex_string(const uint8_t *bytes, int len, char *hex_str) {
    const char *hex_chars = "0123456789abcdef";
    for (int i = 0; i < len; i++) {
        hex_str[i * 2]     = hex_chars[(bytes[i] >> 4) & 0xF];
        hex_str[i * 2 + 1] = hex_chars[bytes[i] & 0xF];
    }
    hex_str[len * 2] = '\0';
}

static int hex_string_to_bytes(const char* hex_str, uint8_t* bytes, int* num_bytes) {
    int len = strlen(hex_str);
    if (len % 2 != 0) {
        return -1;
    }
    *num_bytes = len / 2;
    if (*num_bytes > MAX_CIPHERTEXT_LEN) {
         return -2;
    }

    for (int i = 0; i < *num_bytes; i++) {
        if (sscanf(hex_str + 2 * i, "%2hhx", &bytes[i]) != 1) {
             return -3;
        }
    }
    return 0;
}

CRYPTO_API int run_DES_operation(
    const char* key,
    int mode,
    int isDecrypt,
    int use_text_input,
    const char* input_file,
    const char* input_text,
    int size_of_input_text,
    char* output_file_name,
    char** output_text,
    int* size_of_output_text
) {
    void (*modes_functions[5][2])(const char *, const char *, uint64_t);
    int key_error = 0;
    uint64_t hexKey = hex_string_to_uint64(key, &key_error);

    *output_text = NULL; // אתחול מצביע הפלט
    *size_of_output_text = 0; // אתחול גודל הפלט

    if (key_error != 0) {
        return -1; // קוד שגיאה עבור מפתח
    }

    modes_functions[0][0] = encrypt_file_ECB; modes_functions[0][1] = decrypt_file_ECB;
    modes_functions[1][0] = encrypt_file_CBC; modes_functions[1][1] = decrypt_file_CBC;
    modes_functions[2][0] = encrypt_file_CFB; modes_functions[2][1] = decrypt_file_CFB;
    modes_functions[3][0] = encrypt_file_OFB; modes_functions[3][1] = decrypt_file_OFB;
    modes_functions[4][0] = encrypt_file_CTR; modes_functions[4][1] = decrypt_file_CTR;

    if (use_text_input) {
        if (!isDecrypt) {
            // Encrypt
            if (size_of_input_text < 0 || size_of_input_text > MAX_PLAINTEXT_LEN) {
                 return -4; // קוד שגיאה לגודל קלט חריג
             }

            if (write_bytes_to_temp_file((const uint8_t*)input_text, size_of_input_text, TEMP_FILENAME_IN) != 0) {
                 return -5; // קוד שגיאה לכתיבת קובץ קלט זמני
            }

            modes_functions[mode][0](TEMP_FILENAME_IN, TEMP_FILENAME_OUT, hexKey);

            uint8_t ciphertext_bytes[MAX_CIPHERTEXT_LEN];
            size_t ciphertext_len = read_file_to_bytes(TEMP_FILENAME_OUT, MAX_CIPHERTEXT_LEN, ciphertext_bytes);

            delete_file(TEMP_FILENAME_IN);
            delete_file(TEMP_FILENAME_OUT);

            if (ciphertext_len == 0 && size_of_input_text > 0) { // אם קלט היה ולא היה פלט
                  return -6; // קוד שגיאה לקריאת פלט זמני או פלט ריק
            }

            *size_of_output_text = ciphertext_len * 2;
            *output_text = malloc(*size_of_output_text + 1);
            if (*output_text == NULL) {
                *size_of_output_text = 0;
                return -7; // קוד שגיאה להקצאת זיכרון
            }
            bytes_to_hex_string(ciphertext_bytes, ciphertext_len, *output_text);


        } else {
            // Decrypt
            uint8_t ciphertext_bytes[MAX_CIPHERTEXT_LEN];
            int num_bytes;
            int hex_conversion_error = hex_string_to_bytes(input_text, ciphertext_bytes, &num_bytes);
            if (hex_conversion_error != 0) {
                return -2; // קוד שגיאה להמרת הקסה->בתים
            }

            if (num_bytes < 0 || num_bytes > MAX_CIPHERTEXT_LEN) {
                 return -8; // קוד שגיאה לגודל בתים חריג
             }


            if (write_bytes_to_temp_file(ciphertext_bytes, num_bytes, TEMP_FILENAME_IN) != 0) {
                 return -9; // קוד שגיאה לכתיבת קובץ קלט זמני לפענוח
            }

            modes_functions[mode][1](TEMP_FILENAME_IN, TEMP_FILENAME_OUT, hexKey);

            delete_file(TEMP_FILENAME_IN);
            delete_file(TEMP_FILENAME_OUT);


            char* plaintext = calloc(MAX_PLAINTEXT_LEN + 1, sizeof(char));
            if (plaintext == NULL) {
               return -10; // קוד שגיאה להקצאת זיכרון
            }

            *size_of_output_text = read_text_from_file(TEMP_FILENAME_OUT, MAX_PLAINTEXT_LEN, plaintext);

             if (*size_of_output_text == 0 && num_bytes > 0) { // אם קלט היה ולא היה פלט
                   free(plaintext); // שחרר זיכרון שהוקצה
                   *output_text = NULL;
                   *size_of_output_text = 0;
                   return -11; // קוד שגיאה לקריאת פלט זמני לפענוח
             }

            *output_text = plaintext;


        }
    } else {
        // File mode (לא מטופל במפורש החזרת שגיאות מהמודים הפנימיים)
        modes_functions[mode][isDecrypt](input_file, output_file_name, hexKey);
        // בהנחה שמצב קובץ עובד או לא בשימוש מהאתר
        return 0;
    }

    return 0; // סמן הצלחה
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