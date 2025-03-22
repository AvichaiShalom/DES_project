#include <stdio.h>
#include <stdlib.h>
#include "DES_modes.h"
#include "DES_block.h"
#define IN_FILE "..\\..\\..\\in.txt"
#define ENC_FILE "..\\..\\..\\enc.txt"
#define DEC_FILE "..\\..\\..\\dec.txt"



int isFilesTheSame(const char* file1, const char* file2) {
    FILE* f1 = fopen(file1, "rb");
    FILE* f2 = fopen(file2, "rb");

    if (f1 == NULL || f2 == NULL) {
        // אחד הקבצים לא נמצא
        if (f1 != NULL) fclose(f1);
        if (f2 != NULL) fclose(f2);
        return 0; // החזרת "שקר"
    }

    int ch1, ch2;
    while ((ch1 = fgetc(f1)) != EOF && (ch2 = fgetc(f2)) != EOF) {
        if (ch1 != ch2) {
            fclose(f1);
            fclose(f2);
            return 0; // החזרת "שקר"
        }
    }

    if (fgetc(f1) == EOF && fgetc(f2) == EOF) {
        fclose(f1);
        fclose(f2);
        return 1; // החזרת "אמת"
    } else {
        fclose(f1);
        fclose(f2);
        return 0; // החזרת "שקר"
    }
}

int main() {
	/*
	uint64_t plaintext = 0x123456789ABCDEF0; // קלט לדוגמה
    uint64_t key = 0x133457799BBCDFF1; // מפתח לדוגמה
    uint64_t ciphertext, decrypted_plaintext;

    // הצפנה
    DES_encrypt(plaintext, &ciphertext, key);
    printf("Ciphertext: 0x%lX\n", ciphertext);

    // פענוח
    DES_decrypt(ciphertext, &decrypted_plaintext, key);
    printf("Decrypted plaintext: 0x%lX\n", decrypted_plaintext);

    // בדיקה אם הפענוח תואם לקלט המקורי
    if (plaintext == decrypted_plaintext) {
        printf("DES test passed!\n");
    } else {
        printf("DES test failed!\n");
    }

    return 0;
	*/
	encrypt_file_ECB(IN_FILE, ENC_FILE, 0);
	printf("encrypted ECB\n");
	decrypt_file_ECB(ENC_FILE, DEC_FILE, 0);
	printf("decrypted ECB\n");
	if (isFilesTheSame(IN_FILE, DEC_FILE)) {
		printf("\033[32m ECB passed!!! ;-) \033[0m\n");
	} else {
		printf("\033[31m ECB failed!!! :-( \033[0m\n");
	}
	printf("\n");
	 
	encrypt_file_CBC(IN_FILE, ENC_FILE, 0);
	printf("encrypted CBC\n");
	decrypt_file_CBC(ENC_FILE, DEC_FILE, 0);
	printf("decrypted CBC\n");
	if (isFilesTheSame(IN_FILE, DEC_FILE)) {
		printf("\033[32m CBC passed!!! ;-) \033[0m\n");
	} else {
		printf("\033[31m CBC passed!!! :-( \033[0m\n");
	}
	printf("\n");

	encrypt_file_CFB(IN_FILE, ENC_FILE, 0);
	printf("encrypted CFB\n");
	decrypt_file_CFB(ENC_FILE, DEC_FILE, 0);
	printf("decrypted CFB\n");
	if (isFilesTheSame(IN_FILE, DEC_FILE)) {
		printf("\033[32m CFB passed!!! ;-) \033[0m\n");
	} else {
		printf("\033[31m CFB passed!!! :-( \033[0m\n");
	}
	printf("\n");

	encrypt_file_OFB(IN_FILE, ENC_FILE, 0);
	printf("encrypted OFB\n");
	decrypt_file_OFB(ENC_FILE, DEC_FILE, 0);
	printf("decrypted OFB\n");
	if (isFilesTheSame(IN_FILE, DEC_FILE)) {
		printf("\033[32m OFB passed!!! ;-) \033[0m\n");
	} else {
		printf("\033[31m OFB passed!!! :-( \033[0m\n");
	}
	printf("\n");

	encrypt_file_CTR(IN_FILE, ENC_FILE, 0);
	printf("encrypted CTR\n");
	decrypt_file_CTR(ENC_FILE, DEC_FILE, 0);
	printf("decrypted CTR\n");
	if (isFilesTheSame(IN_FILE, DEC_FILE)) {
		printf("\033[32m CTR passed!!! ;-) \033[0m\n");
	} else {
		printf("\033[31m CTR passed!!! :-( \033[0m\n");
	}



	return 0;
}