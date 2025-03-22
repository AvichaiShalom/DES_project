#include "DES_modes.h"



int main() {
	
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