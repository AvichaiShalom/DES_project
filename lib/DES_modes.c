#include "DES_block.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void add_padding(uint8_t *buffer, size_t bytes_read, uint64_t *block) {
	size_t padding = 8 - bytes_read;

	// מילוי פדינג
	for (size_t i = bytes_read; i < 7; i++) {
		buffer[i] = 0;
	}
	buffer[7] = padding;

	// הצפנה וכתיבה לקובץ
	memcpy(block, buffer, 8);
}

void remove_padding(uint8_t* buffer, size_t* bytes_read) {
	// הקוראים צריכים לדעת את הפדינג מתוך byte האחרון ב-buffer
	size_t padding = buffer[7];
	*bytes_read = 8 - padding;  // אורך המידע האמיתי אחרי הפדינג
}

void encrypt_file_ECB(const char* input_file, const char* output_file, uint64_t key) {
	FILE* input;
	FILE* output;
	uint8_t buffer[8];
	uint64_t block, ciphertext;
	size_t bytes_read;
	size_t i;

	// פתיחת קובץ קלט לקריאה
	input = fopen(input_file, "rb");
	if (!input) {
		perror("Failed to open input file");
		exit(1);
	}

	// פתיחת קובץ פלט לכתיבה
	output = fopen(output_file, "wb");
	if (!output) {
		perror("Failed to open output file");
		fclose(input);
		exit(1);
	}

	// קריאה והצפנה של בלוקים בגודל 8 בתים
	while ((bytes_read = fread(buffer, 1, 8, input)) == 8) {
		memcpy(&block, buffer, 8);
		DES_encrypt(block, &ciphertext, key);
		fwrite(&ciphertext, sizeof(uint64_t), 1, output);
	}

	// טיפול בפדינג
	add_padding(buffer, bytes_read, &block);
	DES_encrypt(block, &ciphertext, key);
	fwrite(&ciphertext, sizeof(uint64_t), 1, output);

	// סגירת קבצים
	fclose(input);
	fclose(output);
}

void decrypt_file_ECB(const char* input_file, const char* output_file, uint64_t key) {
	FILE* input;
	FILE* output;
	uint8_t buffer[8] = {0};
	uint64_t ciphertext = 0, decrypted_block;
	size_t bytes_read;
	size_t numOfBlocks;

	// פתיחת קובץ קלט לקריאה
	input = fopen(input_file, "rb");
	if (!input) {
		perror("Failed to open input file");
		exit(1);
	}

	// פתיחת קובץ פלט לכתיבה
	output = fopen(output_file, "wb");
	if (!output) {
		perror("Failed to open output file");
		fclose(input);
		exit(1);
	}

	fseek(input, 0, SEEK_END);
	numOfBlocks = ftell(input) / 8;
	fseek(input,0,SEEK_SET);

	// קריאה ופעולה על כל הבלוקים חוץ מהאחרון
	while (fread(&ciphertext, sizeof(uint64_t), 1, input) == 1 && numOfBlocks > 1) {
		numOfBlocks--;
		DES_decrypt(ciphertext, &decrypted_block, key);
		fwrite(&decrypted_block, sizeof(uint64_t), 1, output);
	}
	fread(&ciphertext, sizeof(uint64_t), 1, input);
	DES_decrypt(ciphertext, &decrypted_block, key);
	memcpy(buffer, &decrypted_block ,8);

	// קריאת הבלוק האחרון והסרת הפדינג
	remove_padding(buffer, &bytes_read);
	fwrite(buffer, 1, bytes_read, output);

	// סגירת קבצים
	fclose(input);
	fclose(output);
}