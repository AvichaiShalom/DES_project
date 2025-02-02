#include "DES_modes.h"



int main() {
	encrypt_file_ECB("..\\..\\..\\in.txt", "..\\..\\..\\enc.txt", 0);
	printf("encrypted\n");
	decrypt_file_ECB("..\\..\\..\\enc.txt", "..\\..\\..\\dec.txt", 0);
	printf("decrypted\n");
	return 0;
}