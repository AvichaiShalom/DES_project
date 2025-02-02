#include "DES_modes.h"



int main() {
	encrypt_file_CBC("..\\..\\..\\in.txt", "..\\..\\..\\enc.txt", 0);
	printf("encrypted\n");
	decrypt_file_CBC("..\\..\\..\\enc.txt", "..\\..\\..\\dec.txt", 0);
	printf("decrypted\n");
	return 0;
}