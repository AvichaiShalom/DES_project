#include "DES_modes.h"



int main() {
	encrypt_file_OFB("..\\..\\..\\in.txt", "..\\..\\..\\enc.txt", 0);
	printf("encrypted\n");
	decrypt_file_OFB("..\\..\\..\\enc.txt", "..\\..\\..\\dec.txt", 0);
	printf("decrypted\n");
	return 0;
}