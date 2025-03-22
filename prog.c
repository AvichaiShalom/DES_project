#include "DES_modes.h"
#include "DES_block.h"



int main() {
	
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
	
	encrypt_file_ECB("..\\..\\..\\in.txt", "..\\..\\..\\enc.txt", 0);
	printf("encrypted ECB\n");
	decrypt_file_ECB("..\\..\\..\\enc.txt", "..\\..\\..\\dec.txt", 0);
	printf("decrypted ECB\n");

	printf("\n");
	 
	encrypt_file_CBC("..\\..\\..\\in.txt", "..\\..\\..\\enc.txt", 0);
	printf("encrypted CBC\n");
	decrypt_file_CBC("..\\..\\..\\enc.txt", "..\\..\\..\\dec.txt", 0);
	printf("decrypted CBC\n");

	printf("\n");

	encrypt_file_CFB("..\\..\\..\\in.txt", "..\\..\\..\\enc.txt", 0);
	printf("encrypted CFB\n");
	decrypt_file_CFB("..\\..\\..\\enc.txt", "..\\..\\..\\dec.txt", 0);
	printf("decrypted CFB\n");

	printf("\n");

	encrypt_file_OFB("..\\..\\..\\in.txt", "..\\..\\..\\enc.txt", 0);
	printf("encrypted OFB\n");
	decrypt_file_OFB("..\\..\\..\\enc.txt", "..\\..\\..\\dec.txt", 0);
	printf("decrypted OFB\n");

	printf("\n");

	encrypt_file_CTR("..\\..\\..\\in.txt", "..\\..\\..\\enc.txt", 0);
	printf("encrypted CTR\n");
	decrypt_file_CTR("..\\..\\..\\enc.txt", "..\\..\\..\\dec.txt", 0);
	printf("decrypted CTR\n");

	return 0;
}