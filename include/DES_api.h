#ifndef DES_API_H
#define DES_API_H

#ifdef _WIN32
  #ifdef BUILDING_CRYPTO_DLL
    #define CRYPTO_API __declspec(dllexport)
  #else
    #define CRYPTO_API __declspec(dllimport)
  #endif
#else
  #define CRYPTO_API
#endif

CRYPTO_API void run_DES_operation(
    const char *key,
    int mode,           // 0-4
    int isDecrypt,      // 1 = decrypt, 0 = encrypt
    int use_text_input, // 1 = text input, 0 = file
    const char *input_file,
    const char *input_text,
    int size_of_input_text,
    char *output_file_name,
    char **output_text,
    int *size_of_output_text
);

CRYPTO_API void free_output(char *ptr);

#endif