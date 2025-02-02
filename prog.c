#include "DES_modes.h"



int main() {
	encrypt_file_CFB("..\\..\\..\\in.txt", "..\\..\\..\\enc.txt", 0);
	printf("encrypted\n");
	decrypt_file_CFB("..\\..\\..\\enc.txt", "..\\..\\..\\dec.txt", 0);
	printf("decrypted\n");
	return 0;
}