#include <stdio.h>
#include <stdlib.h>
#include "DES_modes.h"
#include "DES_block.h"
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
        {0x1234567890ABCDEF, 0xCAFEBABEDEADBEEF}
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

int main() {
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