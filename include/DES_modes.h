
#ifndef DES_modes
#define DES_modes

#include <stdint.h>
#include <stdio.h>

/*
// פונקציות כלליות
void add_padding(uint8_t *buffer, size_t bytes_read, uint64_t *block);
void remove_padding(uint8_t *buffer, size_t *bytes_read);
*/
// פונקציות עבור מצב ECB
void encrypt_file_ECB(const char *input_file, const char *output_file, uint64_t key);
void decrypt_file_ECB(const char *input_file, const char *output_file, uint64_t key);

// פונקציות עבור מצב CBC
void encrypt_file_CBC(const char *input_file, const char *output_file, uint64_t key);
void decrypt_file_CBC(const char *input_file, const char *output_file, uint64_t key);

// פונקציות עבור מצב CFB
void encrypt_file_CFB(const char *input_file, const char *output_file, uint64_t key);
void decrypt_file_CFB(const char *input_file, const char *output_file, uint64_t key);

// פונקציות עבור מצב OFB
void encrypt_file_OFB(const char *input_file, const char *output_file, uint64_t key);
void decrypt_file_OFB(const char *input_file, const char *output_file, uint64_t key);

// פונקציות עבור מצב CTR
void encrypt_file_CTR(const char *input_file, const char *output_file, uint64_t key);
void decrypt_file_CTR(const char *input_file, const char *output_file, uint64_t key);

#endif