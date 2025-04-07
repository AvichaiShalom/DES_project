#include <stdio.h>
#include <stdlib.h>
#include "DES_modes.h"
#include "DES_block.h"
#include "graph.h"
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