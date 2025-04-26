#ifndef DES_block
#define DES_block

#include <stdint.h>  // עבור הגדרות כמו uint8_t ו-uint64_t



/*פונקציה שמקבלת בלוק בגודל 64 סיביות, מפתח הצפנה בגודל 64 סיביות, מחזירה קלט מוצפן דרך מצביע*/
void DES_encrypt(uint64_t plaintext, uint64_t* ciphertext, uint64_t key);

/*פונקציה שמקבלת בלוק מוצפן בגודל 64 סיביות, מפתח הצפנה בגודל 64 סיביות, מחזירה קלט מפוענח דרך מצביע*/
void DES_decrypt(uint64_t ciphertext, uint64_t* plaintext, uint64_t key);

#endif