#include "../include/DES_modes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PLAINTEXT_LEN 250
#define MAX_CIPHERTEXT_LEN 300
#define TEMP_FILENAME_IN "temp_input.txt"
#define TEMP_FILENAME_OUT "temp_output.txt"

// כותבת טקסט לקובץ זמני, מחזירה את שם הקובץ
void write_text_to_temp_file(const char *text, const char *file_name) {
    FILE* file = fopen(file_name, "w");
    if (!file) {
        perror("Failed to create temp file");
        return NULL;
    }

    fprintf(file, "%s", text);
    fclose(file);
}

// מוחקת קובץ לפי שם
void delete_file(const char* filename) {
    if (remove(filename) != 0) {
        perror("Failed to delete file");
    }
}

// קוראת תוכן מקובץ ומכניסה אותו למשתנה טקסט
size_t read_file_to_text(const char* filename, int max_len, char* out_text) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open file for reading");
        return;
    }

    size_t bytesRead = fread(out_text, sizeof(char), max_len, file);
    out_text[bytesRead] = '\0';  // סיום מחרוזת
    fclose(file);
    return bytesRead;
}

void run_DES_operation(
    const char* key,
    int mode,
    int encrypt,
    int use_text_input,
    const char* input_file,
    const char* input_text,
    char* output_file_name,
    char* output_text,
    int* size_of_output_text
) {
    void (*modes_functions[5][2])(const char *, const char *, uint64_t);

    //ECB
    modes_functions[0][0] = encrypt_file_ECB;
    modes_functions[0][1] = decrypt_file_ECB;

    //CBC
    modes_functions[1][0] = encrypt_file_CBC;
    modes_functions[1][1] = decrypt_file_CBC;

    //CFB
    modes_functions[2][0] = encrypt_file_CFB;
    modes_functions[2][1] = decrypt_file_CFB;

    //OFB
    modes_functions[3][0] = encrypt_file_OFB;
    modes_functions[3][1] = decrypt_file_OFB;

    //CTR
    modes_functions[4][0] = encrypt_file_CTR;
    modes_functions[4][1] = decrypt_file_CTR;
}

char *encrypt_dycrypt_text(char *input_text, void (*mode_function)(const char *, const char *, uint64_t), uint64_t key, int isDecrypt, int *length) {
    char *out;
    int max_out_len;
    if(isDecrypt){
        max_out_len = MAX_PLAINTEXT_LEN;
    } else {
        max_out_len = MAX_CIPHERTEXT_LEN;
    }
    if(!(out = calloc(max_out_len + 1, sizeof(char)))) {
        perror("could not encrypt\\decrypt text");
        exit(1);
    }
    write_text_to_temp_file(input_text, TEMP_FILENAME_IN);
    mode_function(TEMP_FILENAME_IN, TEMP_FILENAME_OUT, key);
    *length = read_file_to_text(TEMP_FILENAME_OUT, MAX_CIPHERTEXT_LEN, out);
    delete_file(TEMP_FILENAME_IN);
    delete_file(TEMP_FILENAME_OUT);
    return out;
}



/*
    תיקונים

    מה שכותבים לתוך טקסט בהצפנה זה הקסה
    אז צריך לקרא תו תו
    בפונקציה של קריאת טקסט מקובץ

    לתקן פונקציה של טקסט, לעשות שתהיה גנרית בעבור הצפנה\פענוח
*/