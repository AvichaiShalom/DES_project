#include "../include/DES_block.h"
#include "../include/constants.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void add_padding(uint8_t *buffer, size_t bytes_read, uint64_t *block) {
	size_t padding = BLOCK_SIZE_BYTES - bytes_read;
	size_t i;

	// מילוי פדינג
	for (i = bytes_read; i < BLOCK_SIZE_BYTES - 1; i++) {
		buffer[i] = 0;
	}
	buffer[BLOCK_SIZE_BYTES - 1] = padding;
	
	memcpy(block, buffer, BLOCK_SIZE_BYTES);
}

void remove_padding(uint8_t* buffer, size_t* bytes_read) {
	// הקוראים צריכים לדעת את הפדינג מתוך byte האחרון ב-buffer
	size_t padding = buffer[BLOCK_SIZE_BYTES - 1];
	*bytes_read = BLOCK_SIZE_BYTES - padding;  // אורך המידע האמיתי אחרי הפדינג
}

void encrypt_file_ECB(const char* input_file, const char* output_file, uint64_t key) {
	FILE* input;
	FILE* output;
	uint8_t buffer[BLOCK_SIZE_BYTES];
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
	while ((bytes_read = fread(buffer, 1, BLOCK_SIZE_BYTES, input)) == BLOCK_SIZE_BYTES) {
		memcpy(&block, buffer, BLOCK_SIZE_BYTES);
		DES_encrypt(block, &ciphertext, key);
		fwrite(&ciphertext, BLOCK_SIZE_BYTES, 1, output);
	}

	// טיפול בפדינג
	add_padding(buffer, bytes_read, &block);
	DES_encrypt(block, &ciphertext, key);
	fwrite(&ciphertext, BLOCK_SIZE_BYTES, 1, output);

	// סגירת קבצים
	fclose(input);
	fclose(output);
}

void decrypt_file_ECB(const char* input_file, const char* output_file, uint64_t key) {
	FILE* input;
	FILE* output;
	uint8_t buffer[BLOCK_SIZE_BYTES];
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
	numOfBlocks = ftell(input) / BLOCK_SIZE_BYTES;
	fseek(input,0,SEEK_SET);

	// קריאה ופעולה על כל הבלוקים חוץ מהאחרון
	while (fread(&ciphertext, BLOCK_SIZE_BYTES, 1, input) == 1 && numOfBlocks > 1) {
		numOfBlocks--;
		DES_decrypt(ciphertext, &decrypted_block, key);
		fwrite(&decrypted_block, BLOCK_SIZE_BYTES, 1, output);
	}
	fread(&ciphertext, BLOCK_SIZE_BYTES, 1, input);
	DES_decrypt(ciphertext, &decrypted_block, key);
	memcpy(buffer, &decrypted_block ,BLOCK_SIZE_BYTES);

	// קריאת הבלוק האחרון והסרת הפדינג
	remove_padding(buffer, &bytes_read);
	fwrite(buffer, 1, bytes_read, output);

	// סגירת קבצים
	fclose(input);
	fclose(output);
}

void encrypt_file_CBC(const char *input_file, const char *output_file, uint64_t key) {
	FILE* input;
	FILE* output;
	uint8_t buffer[BLOCK_SIZE_BYTES];
	uint64_t block, ciphertext;
	size_t bytes_read;
	size_t i;
	uint8_t iv[BLOCK_SIZE_BYTES];

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

	srand(time(NULL));
	for (i = 0; i < BLOCK_SIZE_BYTES; i++) {
		iv[i] = rand() % 256;
	}
	memcpy(&ciphertext, iv, BLOCK_SIZE_BYTES);
	fwrite(&ciphertext, BLOCK_SIZE_BYTES, 1, output);

	while ((bytes_read = fread(buffer, 1, BLOCK_SIZE_BYTES, input)) == BLOCK_SIZE_BYTES) {
		memcpy(&block, buffer, 8);
		block ^= ciphertext;
		DES_encrypt(block, &ciphertext, key);
		fwrite(&ciphertext, BLOCK_SIZE_BYTES, 1, output);
	}

	// טיפול בפדינג
	add_padding(buffer, bytes_read, &block);
	block ^= ciphertext;
	DES_encrypt(block, &ciphertext, key);
	fwrite(&ciphertext, BLOCK_SIZE_BYTES, 1, output);

	// סגירת קבצים
	fclose(input);
	fclose(output);
}

void decrypt_file_CBC(const char *input_file, const char *output_file, uint64_t key) {
	FILE* input;
	FILE* output;
	uint8_t buffer[BLOCK_SIZE_BYTES];
	uint64_t ciphertext = 0, decrypted_block;
	size_t bytes_read;
	size_t numOfBlocks;
	uint64_t iv;

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

	fread(&iv, BLOCK_SIZE_BYTES, 1, input);

	fseek(input, 0, SEEK_END);
	numOfBlocks = ftell(input) / BLOCK_SIZE_BYTES - 1;
	fseek(input, BLOCK_SIZE_BYTES, SEEK_SET);

	// קריאה ופעולה על כל הבלוקים חוץ מהאחרון
	while (fread(&ciphertext, BLOCK_SIZE_BYTES, 1, input) == 1 && numOfBlocks > 1) {
		numOfBlocks--;
		DES_decrypt(ciphertext, &decrypted_block, key);
		decrypted_block ^= iv;
		iv = ciphertext;
		fwrite(&decrypted_block, BLOCK_SIZE_BYTES, 1, output);
	}
	fread(&ciphertext, BLOCK_SIZE_BYTES, 1, input);
	DES_decrypt(ciphertext, &decrypted_block, key);
	decrypted_block ^= iv;
	memcpy(buffer, &decrypted_block ,8);

	// קריאת הבלוק האחרון והסרת הפדינג
	remove_padding(buffer, &bytes_read);
	fwrite(buffer, 1, bytes_read, output);

	// סגירת קבצים
	fclose(input);
	fclose(output);
}

void encrypt_file_CFB(const char *input_file, const char *output_file, uint64_t key) {
	FILE* input;
	FILE* output;
	uint8_t buffer[BLOCK_SIZE_BYTES];
	uint64_t block, ciphertext;
	size_t bytes_read;
	size_t i;
	uint8_t iv[BLOCK_SIZE_BYTES];

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

	srand(time(NULL));
	for (i = 0; i < BLOCK_SIZE_BYTES; i++) {
		iv[i] = rand() % 256;
	}
	memcpy(&block, iv, 8);
	fwrite(&block, BLOCK_SIZE_BYTES, 1, output);

	while ((bytes_read = fread(buffer, 1, BLOCK_SIZE_BYTES, input)) == BLOCK_SIZE_BYTES) {
		DES_encrypt(block, &ciphertext, key);
		memcpy(&block, buffer, 8);
		block ^= ciphertext;
		fwrite(&block, BLOCK_SIZE_BYTES, 1, output);
	}

	// טיפול בפדינג
	DES_encrypt(block, &ciphertext, key);
	add_padding(buffer, bytes_read, &block);
	block ^= ciphertext;
	fwrite(&block, BLOCK_SIZE_BYTES, 1, output);

	// סגירת קבצים
	fclose(input);
	fclose(output);
}

void decrypt_file_CFB(const char *input_file, const char *output_file, uint64_t key) {
	FILE* input;
	FILE* output;
	uint8_t buffer[BLOCK_SIZE_BYTES];
	uint64_t ciphertext = 0, decrypted_block;
	size_t bytes_read;
	size_t numOfBlocks;
	uint64_t last_block;

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

	fread(&last_block, BLOCK_SIZE_BYTES, 1, input);

	fseek(input, 0, SEEK_END);
	numOfBlocks = ftell(input) / BLOCK_SIZE_BYTES - 1;
	fseek(input, BLOCK_SIZE_BYTES, SEEK_SET);

	while (fread(&ciphertext, BLOCK_SIZE_BYTES, 1, input) == 1 && numOfBlocks > 1) {
		numOfBlocks--;
		DES_encrypt(last_block, &decrypted_block, key);
		decrypted_block ^= ciphertext;
		last_block = ciphertext;
		fwrite(&decrypted_block, BLOCK_SIZE_BYTES, 1, output);
	}

	fread(&ciphertext, BLOCK_SIZE_BYTES, 1, input);
	DES_encrypt(last_block, &decrypted_block, key);
	decrypted_block ^= ciphertext;
	memcpy(buffer, &decrypted_block ,BLOCK_SIZE_BYTES);

	// קריאת הבלוק האחרון והסרת הפדינג
	remove_padding(buffer, &bytes_read);
	fwrite(buffer, 1, bytes_read, output);

	// סגירת קבצים
	fclose(input);
	fclose(output);
}

void encrypt_file_OFB(const char *input_file, const char *output_file, uint64_t key) {
	FILE* input;
	FILE* output;
	uint8_t buffer[BLOCK_SIZE_BYTES];
	uint64_t block, encIV, iv;
	size_t bytes_read;
	size_t i;
	uint8_t ivFirstVsl[BLOCK_SIZE_BYTES];

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

	srand(time(NULL));
	for (i = 0; i < BLOCK_SIZE_BYTES; i++) {
		ivFirstVsl[i] = rand() % 256;
	}

	memcpy(&iv, ivFirstVsl, BLOCK_SIZE_BYTES);
	fwrite(&iv, BLOCK_SIZE_BYTES, 1, output);

	while ((bytes_read = fread(buffer, 1, BLOCK_SIZE_BYTES, input)) == BLOCK_SIZE_BYTES) {
		DES_encrypt(iv, &encIV, key);
		iv = encIV;
		memcpy(&block, buffer, BLOCK_SIZE_BYTES);
		block ^= iv;
		fwrite(&block, BLOCK_SIZE_BYTES, 1, output);
	}

	// טיפול בפדינג
	DES_encrypt(iv, &encIV, key);
	add_padding(buffer, bytes_read, &block);
	block ^= encIV;
	fwrite(&block, BLOCK_SIZE_BYTES, 1, output);

	// סגירת קבצים
	fclose(input);
	fclose(output);
}

void decrypt_file_OFB(const char *input_file, const char *output_file, uint64_t key) {
	FILE* input;
    FILE* output;
    uint8_t buffer[BLOCK_SIZE_BYTES];
	uint64_t ciphertext, plaintext, encIV;
    size_t bytes_read;
    uint64_t iv;
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

	fread(&iv, BLOCK_SIZE_BYTES, 1, input);

	fseek(input, 0, SEEK_END);
	numOfBlocks = ftell(input) / BLOCK_SIZE_BYTES - 1;
	fseek(input, BLOCK_SIZE_BYTES, SEEK_SET);

	while (fread(&ciphertext, BLOCK_SIZE_BYTES, 1, input) == 1 && numOfBlocks > 1) {
		numOfBlocks--;
		DES_encrypt(iv, &encIV, key);
		iv = encIV;
		plaintext = ciphertext ^ encIV;
        fwrite(&plaintext, BLOCK_SIZE_BYTES, 1, output);
	}
	// טיפול בפדינג
	fread(&ciphertext, BLOCK_SIZE_BYTES, 1, input);
	DES_encrypt(iv, &encIV, key);
	plaintext = ciphertext ^ encIV;
	memcpy(buffer, &plaintext, BLOCK_SIZE_BYTES);
	remove_padding(buffer, &bytes_read);
	fwrite(buffer, 1, bytes_read, output);

	// סגירת קבצים
	fclose(input);
	fclose(output);
}

void encrypt_file_CTR(const char *input_file, const char *output_file, uint64_t key) {
	FILE* input;
    FILE* output;
    uint8_t buffer[BLOCK_SIZE_BYTES];
	uint64_t block, encCTR;
	size_t bytes_read;
	size_t i;
	char nonceArr[INT_4_BYTES];
	uint32_t nonce, counter = 0;

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

	srand(time(NULL));
	for (i = 0; i < INT_4_BYTES; i++) {
		nonceArr[i] = rand() % 256;
	}
	memcpy(&nonce, nonceArr, INT_4_BYTES);

	fwrite(&nonce, INT_4_BYTES, 1, output);

	while ((bytes_read = fread(buffer, 1, BLOCK_SIZE_BYTES, input)) == BLOCK_SIZE_BYTES) {
		DES_encrypt(((uint64_t)(nonce) << INT_32_BITS) | counter, &encCTR, key);
		memcpy(&block, buffer, BLOCK_SIZE_BYTES);
		block ^= encCTR;
		fwrite(&block, BLOCK_SIZE_BYTES, 1, output);
		counter++;
	}
	// טיפול בפדינג
	DES_encrypt(((uint64_t)(nonce) << INT_32_BITS) | counter, &encCTR, key);
	add_padding(buffer, bytes_read, &block);
	block ^= encCTR;
	fwrite(&block, BLOCK_SIZE_BYTES, 1, output);

	// סגירת קבצים
	fclose(input);
	fclose(output);
}

void decrypt_file_CTR(const char *input_file, const char *output_file, uint64_t key) {
	FILE* input;
    FILE* output;
    uint8_t buffer[BLOCK_SIZE_BYTES];
	uint64_t block, encCTR;
	size_t bytes_read;
	uint32_t nonce, counter = 0;
	size_t numOfBlocks;

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

	fread(&nonce, INT_4_BYTES, 1, input);

	fseek(input, 0, SEEK_END);
	numOfBlocks = (ftell(input) - INT_4_BYTES) / BLOCK_SIZE_BYTES;
	fseek(input, INT_4_BYTES, SEEK_SET);

	while (fread(&block, BLOCK_SIZE_BYTES, 1, input) == 1 && numOfBlocks > 1) {
		numOfBlocks--;
		DES_encrypt(((uint64_t)(nonce) << INT_32_BITS) | counter, &encCTR, key);
		block ^= encCTR;
        fwrite(&block, BLOCK_SIZE_BYTES, 1, output);
		counter++;
	}
	// טיפול בפדינג
	fread(&block, BLOCK_SIZE_BYTES, 1, input);
	DES_encrypt(((uint64_t)(nonce) << INT_32_BITS) | counter, &encCTR, key);
	block ^= encCTR;
	memcpy(buffer, &block, BLOCK_SIZE_BYTES);
	remove_padding(buffer, &bytes_read);
	fwrite(buffer, 1, bytes_read, output);

	// סגירת קבצים
	fclose(input);
	fclose(output);
}