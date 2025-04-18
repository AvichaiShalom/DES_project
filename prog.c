
#include <stdio.h>
#include <stdlib.h>
#include "DES_modes_file.h"
#include "DES_modes_text.h"
#include "DES_block.h"
#include "graph.h"
#include "DES_api.h"
#define IN_FILE "..\\..\\..\\in.txt"
#define ENC_FILE "..\\..\\..\\enc.txt"
#define DEC_FILE "..\\..\\..\\dec.txt"
#define KEY 0



int isFilesTheSame(const char* file1, const char* file2) {
    FILE* f1 = fopen(file1, "rb");
    FILE* f2 = fopen(file2, "rb");

    if (f1 == NULL || f2 == NULL) {
        // אחד הקבצים לא נמצא
        if (f1 != NULL) fclose(f1);
        if (f2 != NULL) fclose(f2);
        return 0; // false
    }

    int ch1, ch2;
    while ((ch1 = fgetc(f1)) != EOF && (ch2 = fgetc(f2)) != EOF) {
        if (ch1 != ch2) {
            fclose(f1);
            fclose(f2);
            return 0; // false
        }
    }

    if (fgetc(f1) == EOF && fgetc(f2) == EOF) {
        fclose(f1);
        fclose(f2);
        return 1; // true
    } else {
        fclose(f1);
        fclose(f2);
        return 0; // false
    }
}
/*
typedef struct {
    uint64_t plaintext;
    uint64_t key;
} TestVector;

void run_des_tests() {
    TestVector tests[] = {
        {0x923456789ABCDEF0, 0x133457799BBCDFF2},
        {0x0123456789ABCDEF, 0x0F1571C947D9E859},
        {0xFFFFFFFFFFFFFFFF, 0x0000000000000000},
        {0x0000000000000000, 0xFFFFFFFFFFFFFFFF},
        {0xFEDCBA9876543210, 0xAABB09182736CCDD},
        {0xAAAAAAAAAAAAAAAA, 0x5555555555555555},
        {0x1234567890ABCDEF, 0xCAFEBABEDEADBEEF},
        {0x0000000000000001, 0x1234567890ABCDEF},
        {0x1111111111111111, 0x0F0F0F0F0F0F0F0F},
        {0x2222222222222222, 0x1A2B3C4D5E6F7A8B},
        {0x3333333333333333, 0x4E5F6D7C8A9B0F1C},
        {0x4444444444444444, 0x9876543210ABCDEF},
        {0x5555555555555555, 0x1F2E3D4C5B6A7E8F},
        {0x6666666666666666, 0xABCDEF0123456789},
        {0x7777777777777777, 0x12345ABCDE987654}
    };

    int total_tests = sizeof(tests) / sizeof(TestVector);
    int passed_tests = 0;

    printf("Running %d DES test vectors...\n\n", total_tests);

    for (int i = 0; i < total_tests; i++) {
        uint64_t ciphertext = 0;
        uint64_t decrypted_plaintext = 0;

        DES_encrypt(tests[i].plaintext, &ciphertext, tests[i].key);
        DES_decrypt(ciphertext, &decrypted_plaintext, tests[i].key);

        printf("Test #%d\n", i + 1);
        printf("  Plaintext:  0x%016lX\n", tests[i].plaintext);
        printf("  Key:        0x%016lX\n", tests[i].key);
        printf("  Ciphertext: 0x%016lX\n", ciphertext);
        printf("  Decrypted:  0x%016lX\n", decrypted_plaintext);

        if (tests[i].plaintext == decrypted_plaintext) {
            printf("  Result:     PASS\n\n");
            passed_tests++;
        } else {
            printf("  Result:     FAIL\n\n");
        }
    }

    printf("Summary: %d/%d tests passed.\n", passed_tests, total_tests);
}


#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define S_BOXES_COUNT 8
#define S_BOXES_ROWS 4
#define S_BOXES_COLS 16

int validate_row(int row[S_BOXES_COLS]) {
    int seen[S_BOXES_COLS] = {0};
    for (int i = 0; i < S_BOXES_COLS; i++) {
        int val = row[i];
        if (val < 0 || val >= S_BOXES_COLS) return 0; // ערך מחוץ לתחום
        if (seen[val]) return 0; // הופיע פעמיים
        seen[val] = 1;
    }
    return 1; // השורה תקינה
}

int validate_sboxes(int sboxes[S_BOXES_COUNT][S_BOXES_ROWS][S_BOXES_COLS]) {
    for (int i = 0; i < S_BOXES_COUNT; i++) {
        for (int j = 0; j < S_BOXES_ROWS; j++) {
            if (!validate_row(sboxes[i][j])) {
                printf("Error in S-Box %d, row %d: not a valid permutation\n", i + 1, j);
                return 0;
            }
        }
    }
    return 1;
}

int compare_sboxes(int a[S_BOXES_COUNT][S_BOXES_ROWS][S_BOXES_COLS], int b[S_BOXES_COUNT][S_BOXES_ROWS][S_BOXES_COLS]) {
    return memcmp(a, b, sizeof(int) * S_BOXES_COUNT * S_BOXES_ROWS * S_BOXES_COLS) == 0;
}

void test_sbox_generation() {
    int sboxes1[S_BOXES_COUNT][S_BOXES_ROWS][S_BOXES_COLS];
    int sboxes2[S_BOXES_COUNT][S_BOXES_ROWS][S_BOXES_COLS];

    srand(0xDEADBEEF); // מפתח לדוגמה
    generate_sboxes(sboxes1);

    srand(0xDEADBEEF); // אותו מפתח שוב
    generate_sboxes(sboxes2);

    if (!validate_sboxes(sboxes1)) {
        printf("Validation failed: S-Boxes contain invalid rows\n");
        return;
    }

    if (!compare_sboxes(sboxes1, sboxes2)) {
        printf("Validation failed: S-Boxes not deterministic\n");
        return;
    }

    printf("S-Box generation test passed!\n");
}


int main() {
    char *out;
    int out_len;
    run_DES_operation(
        "0123456789ABCDEF", // key
        0,                  // mode (ECB)
        0,                  // encrypt
        1,                  // text input
        NULL,               // input_file
        "hello world",      // input_text
        strlen("hello world"), // size_of_input_text
        NULL,               // output_file_name
        &out,               // output_text
        &out_len            // size_of_output_text
    );
    for (int i = 0; i < out_len; i++) {
        printf("%c", out[i]);
    }
    printf("\n%d\n", out_len);

    char *decrypted;
    int decrypted_len;
    
    run_DES_operation(
        "0123456789ABCDEF",  // אותו מפתח
        0,                   // ECB
        1,                   // פענוח
        1,                   // קלט מטקסט
        NULL,                // אין קובץ קלט
        out,                 // הטקסט המוצפן ב-hex
        strlen(out),         // גודל הטקסט (hex)
        NULL,                // אין קובץ פלט
        &decrypted,          // מצביע לתוצאה
        &decrypted_len       // גודל הפלט
    );
    
    // הדפסת הטקסט המפוענח
    printf("Decrypted: ");
    for (int i = 0; i < decrypted_len; i++) {
        printf("%c", decrypted[i]);
    }
    printf("\n");

    run_DES_operation(
        "0123456789ABCDEF", // המפתח
        0,                  // ECB
        0,                  // הצפנה
        0,                  // קלט מקובץ
        IN_FILE,            // <<< תחליף בשם של קובץ הקלט
        NULL,               // לא צריך טקסט קלט
        0,                  // לא רלוונטי
        ENC_FILE,           // <<< תן שם לקובץ המוצפן
        NULL,               // לא צריך פלט לטקסט
        NULL                // לא צריך גודל פלט
    );

    run_DES_operation(
        "0123456789ABCDEF",   // אותו מפתח
        0,                    // ECB
        1,                    // פענוח
        0,                    // קלט מקובץ
        ENC_FILE, // <<< זה הקובץ המוצפן שיצרת למעלה
        NULL,                 // אין טקסט קלט
        0,                    // לא רלוונטי
        DEC_FILE, // <<< תן שם לקובץ שיקבל את הפלט
        NULL,                 // לא צריך פלט לטקסט
        NULL                  // לא צריך גודל פלט
    );

    return 0;



    //test_sbox_generation();
    run_des_tests();
	return 0;
	

	encrypt_file_ECB(IN_FILE, ENC_FILE, KEY);
	printf("encrypted ECB\n");
	decrypt_file_ECB(ENC_FILE, DEC_FILE, KEY);
	printf("decrypted ECB\n");
	if (isFilesTheSame(IN_FILE, DEC_FILE)) {
		printf("\033[32m ECB passed!!! ;-) \033[0m\n");
	} else {
		printf("\033[31m ECB failed!!! :-( \033[0m\n");
	}
	printf("\n");
	 
	encrypt_file_CBC(IN_FILE, ENC_FILE, KEY);
	printf("encrypted CBC\n");
	decrypt_file_CBC(ENC_FILE, DEC_FILE, KEY);
	printf("decrypted CBC\n");
	if (isFilesTheSame(IN_FILE, DEC_FILE)) {
		printf("\033[32m CBC passed!!! ;-) \033[0m\n");
	} else {
		printf("\033[31m CBC passed!!! :-( \033[0m\n");
	}
	printf("\n");

	encrypt_file_CFB(IN_FILE, ENC_FILE, KEY);
	printf("encrypted CFB\n");
	decrypt_file_CFB(ENC_FILE, DEC_FILE, KEY);
	printf("decrypted CFB\n");
	if (isFilesTheSame(IN_FILE, DEC_FILE)) {
		printf("\033[32m CFB passed!!! ;-) \033[0m\n");
	} else {
		printf("\033[31m CFB passed!!! :-( \033[0m\n");
	}
	printf("\n");

	encrypt_file_OFB(IN_FILE, ENC_FILE, KEY);
	printf("encrypted OFB\n");
	decrypt_file_OFB(ENC_FILE, DEC_FILE, KEY);
	printf("decrypted OFB\n");
	if (isFilesTheSame(IN_FILE, DEC_FILE)) {
		printf("\033[32m OFB passed!!! ;-) \033[0m\n");
	} else {
		printf("\033[31m OFB passed!!! :-( \033[0m\n");
	}
	printf("\n");

	encrypt_file_CTR(IN_FILE, ENC_FILE, KEY);
	printf("encrypted CTR\n");
	decrypt_file_CTR(ENC_FILE, DEC_FILE, KEY);
	printf("decrypted CTR\n");
	if (isFilesTheSame(IN_FILE, DEC_FILE)) {
		printf("\033[32m CTR passed!!! ;-) \033[0m\n");
	} else {
		printf("\033[31m CTR passed!!! :-( \033[0m\n");
	}



	return 0;
}


int main() {
    const char* key = "0123456789ABCDEF";
    const char* input = "Hello, World!123";

    for (int mode = 0; mode <= 4; mode++) {
        printf("=== MODE %d ===\n", mode);

        // --- טקסט ---
        char* out;
        int out_len;

        run_DES_operation(
            key,
            mode,
            0,
            1,
            NULL,
            input,
            strlen(input),
            NULL,
            &out,
            &out_len
        );

        printf("%s\n", out);
        printf("%d\n", out_len);

        char* decrypted;
        int decrypted_len;

        run_DES_operation(
            key,
            mode,
            1,
            1,
            NULL,
            out,
            out_len,
            NULL,
            &decrypted,
            &decrypted_len
        );

        if (strncmp(input, decrypted, strlen(input)) == 0) {
            printf("[TEXT] OK \n");
        } else {
            printf("[TEXT] FAIL \nOriginal: %s\nDecrypted: %s\n", input, decrypted);
        }

        free(out);
        free(decrypted);

        // --- קובץ ---
        run_DES_operation(
            key,
            mode,
            0,
            0,
            IN_FILE,
            NULL,
            0,
            ENC_FILE,
            NULL,
            NULL
        );

        run_DES_operation(
            key,
            mode,
            1,
            0,
            ENC_FILE,
            NULL,
            0,
            DEC_FILE,
            NULL,
            NULL
        );

        if (isFilesTheSame(IN_FILE, DEC_FILE)) {
            printf("[FILE] OK \n");
        } else {
            printf("[FILE] FAIL \n");
        }

        printf("\n");
    }

    return 0;
}
*/

int main() {
    char *encrypted;
    int encrypted_len;

    const char* key = "133457799BBCDFF1";
    const char* plaintext = "Hello, World!";
    int result = DES_text((char*)key, 0, 0, (char*)plaintext, strlen(plaintext), &encrypted, &encrypted_len);

    if (result == 0) {
        printf("Encrypted (hex): %s\n", encrypted);
        char* decrypted;
        int decrypted_len;

        DES_text((char*)key, 0, 1, encrypted, encrypted_len, &decrypted, &decrypted_len);
        printf("Decrypted: %.*s\n", decrypted_len, decrypted);

        free(encrypted);
        free(decrypted);
    } else {
        printf("DES_text failed with code: %d\n", result);
    }

    return 0;
}
