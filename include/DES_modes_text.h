#ifndef DES_modes_t
#define DES_modes_t

#include <stdint.h>
#include <stdio.h>

void encrypt_buffer_ECB(char* buffer, int buffer_length, uint64_t key, char** out_buffer, int* out_buffer_length);
void decrypt_buffer_ECB(char* buffer, int buffer_length, uint64_t key, char** out_buffer, int* out_buffer_length);

void encrypt_buffer_CBC(char* buffer, int buffer_length, uint64_t key, char** out_buffer, int* out_buffer_length);
void decrypt_buffer_CBC(char* buffer, int buffer_length, uint64_t key, char** out_buffer, int* out_buffer_length);

void encrypt_buffer_CFB(char* buffer, int buffer_length, uint64_t key, char** out_buffer, int* out_buffer_length);
void decrypt_buffer_CFB(char* buffer, int buffer_length, uint64_t key, char** out_buffer, int* out_buffer_length);

void encrypt_buffer_OFB(char* buffer, int buffer_length, uint64_t key, char** out_buffer, int* out_buffer_length);
void decrypt_buffer_OFB(char* buffer, int buffer_length, uint64_t key, char** out_buffer, int* out_buffer_length);

void encrypt_buffer_CTR(char* buffer, int buffer_length, uint64_t key, char** out_buffer, int* out_buffer_length);
void decrypt_buffer_CTR(char* buffer, int buffer_length, uint64_t key, char** out_buffer, int* out_buffer_length);

#endif