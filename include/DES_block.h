#include <stdint.h>  // עבור הגדרות כמו uint8_t ו-uint64_t



// פונקציה לתחילת האלגוריתם שמקבלת קלט, מפתח, ומצביע לפלט
void DES_encrypt(uint64_t plaintext, uint64_t* ciphertext, uint64_t key);

// פונקציה לפענוח שמקבלת קלט מוצפן, מפתח, ומחזירה את הטקסט המקורי
void DES_decrypt(uint64_t ciphertext, uint64_t* plaintext, uint64_t key);


/*
// שלבים עיקריים:

// שלב ההמרה הראשונית (Initial Permutation)
void initial_permutation(uint64_t data, uint64_t* permuted_data);

// שלב ההמרה הסופית (Final Permutation)
void final_permutation(uint64_t data, uint64_t* permuted_data);

// חלוקה לשני חלקים עבור ההצפנה (L ו-R) - 32 ביט כל אחד
void split_blocks(uint64_t block, uint32_t* L, uint32_t* R);

// מיזוג החלקים חזרה לבלוק אחד
void merge_blocks(uint32_t L, uint32_t R, uint64_t* block);

// יצירת תתי המפתחות (subkeys)
void generate_subkeys(uint64_t key, uint64_t subkeys[16]);

// פונקציית ההזזה השמאלית עבור יצירת תתי המפתחות (ל-28 ביט)
void left_shift(uint32_t* half_key, int shift_amount);

// פונקציית ה-PC-1 להמרה ראשונית של המפתח
void permuted_choice_1(uint64_t key, uint64_t* permuted_key);

// פונקציית ה-PC-2 להמרה הסופית של המפתח ליצירת תתי המפתחות
void permuted_choice_2(uint64_t key, uint64_t* subkey);

// פונקציית ההרחבה עבור החלק הימני (R) מ-32 ביטים ל-48 ביטים
void expansion_function(uint32_t R, uint64_t* expanded_R);

// פונקציית ה-f שמקבלת את החלק הימני ואת תת המפתח ומחזירה את הפלט
void f_function(uint32_t R, uint64_t subkey, uint32_t* f_result);

// פונקציית ה-S-Box: מפעילה את טבלאות ההחלפה על החלק הימני המורחב
void s_box_substitution(uint64_t input, uint32_t* output);

// פונקציית החלפה (P) שמשמשת לאחר ה-S-Boxes להמרת הביטים
void permutation_function(uint32_t data, uint32_t* permuted_data);
*/