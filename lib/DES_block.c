#include <stdint.h>
#include <stdlib.h>
#include "../include/graph.h"
#include "../include/constants.h"


// מבצע חילופים ראשוניים על הפלט
static void initial_permutation(uint64_t data, uint64_t* permuted_data) {
	int i;
	int IP[] = {
		58, 50, 42, 34, 26, 18, 10, 2,
		60, 52, 44, 36, 28, 20, 12, 4,
		62, 54, 46, 38, 30, 22, 14, 6,
		64, 56, 48, 40, 32, 24, 16, 8,
		57, 49, 41, 33, 25, 17, 9, 1,
		59, 51, 43, 35, 27, 19, 11, 3,
		61, 53, 45, 37, 29, 21, 13, 5,
		63, 55, 47, 39, 31, 23, 15, 7
	};
	*permuted_data = 0;
	
	for (i = 0;i < BLOCK_SIZE_BITS;i++) {
		//takes the bit in the i pos in the input and put it in the IP[i] pos in the output
		*permuted_data |= ((data >> (IP[i] - 1)) & 1) << i;
	}
}

// מבצע חילופים סופיים
static void final_permutation(uint64_t data, uint64_t* permuted_data) {
	int i;
	int FP[] = {
		40, 8, 48, 16, 56, 24, 64, 32,
		39, 7, 47, 15, 55, 23, 63, 31,
		38, 6, 46, 14, 54, 22, 62, 30,
		37, 5, 45, 13, 53, 21, 61, 29,
		36, 4, 44, 12, 52, 20, 60, 28,
		35, 3, 43, 11, 51, 19, 59, 27,
		34, 2, 42, 10, 50, 18, 58, 26,
		33, 1, 41, 9, 49, 17, 57, 25
	};
	*permuted_data = 0;

	for (i = 0;i < BLOCK_SIZE_BITS;i++) {
		//takes the bit in the i pos in the input and put it in the FP[i] pos in the output
		*permuted_data |= ((data >> (FP[i] - 1)) & 1) << i;
	}
}

// מחלק את הבלוק לשני חצאיפ ושם אותם במצביעים
static void split_blocks(uint64_t block, uint32_t* L, uint32_t* R) {
	*R = block & RIGHT_HALF_BLOCK_ON;
	*L = (block & LEFT_HALF_BLOCK_ON) >> HALF_BLOCK_SIZE_BITS;
}

// מקבל שני חצאי בלוק ושרשר אותם לבלוק אחד
static void merge_blocks(uint32_t L, uint32_t R, uint64_t* block) {
	*block = R;
	*block |= (uint64_t)(L) << HALF_BLOCK_SIZE_BITS;
}

// מבצע חילופים על המפתח, ממיר את גודלו מ64 סיסיות ל56 סיביות
static void permuted_choice_1(uint64_t key, uint64_t* permuted_key) {
	int i;
	int PC1[] = {
		57, 49, 41, 33, 25, 17, 9,
		1, 58, 50, 42, 34, 26, 18,
		10, 2, 59, 51, 43, 35, 27,
		19, 11, 3, 60, 52, 44, 36,
		63, 55, 47, 39, 31, 23, 15,
		7, 62, 54, 46, 38, 30, 22,
		14, 6, 61, 53, 45, 37, 29,
		21, 13, 5, 28, 20, 12, 4
	};
	*permuted_key = 0;

	for (i = 0;i < KEY_SIZE_BITS;i++) {
		//takes the bit in the pc1[i] pos in the input and put it in the i pos in the output
		*permuted_key |= ((key >> (PC1[i] - 1)) & 1) << i;
	}
}

// ממיר מפתח בגודל 56 סיביות לתת מפתח בגודל 48 סיביות
static void permuted_choice_2(uint64_t key, uint64_t* subkey) {
	int i;
	int PC2[] = {
		14, 17, 11, 24, 1, 5,
		3, 28, 15, 6, 21, 10,
		23, 19, 12, 4, 26, 8,
		16, 7, 27, 20, 13, 2,
		41, 52, 31, 37, 47, 55,
		30, 40, 51, 45, 33, 48,
		44, 49, 39, 56, 34, 53,
		46, 42, 50, 36, 29, 32
	};
	*subkey = 0;

	for (i = 0;i < SUBKEY_SIZE_BITS;i++) {
		//takes the bit in the pc2[i] pos in the input and put it in the i pos in the output
		*subkey |= ((key >> (PC2[i] - 1)) & 1) << i;
	}
}

// מבצע סיסוב מעגלי שמאלה
static void left_shift(uint32_t* half_key, int shift_amount) {
	*half_key = (*half_key << shift_amount) | (*half_key >> (HALF_KEY_SIZE_BITS - shift_amount));
}

// יוצר תתי מפתחות
static void generate_subkeys(uint64_t key, uint64_t subkeys[16]) {
	uint64_t permuted_key;
	uint64_t combined_key;
	uint32_t left, right;
	int shifts[] = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
	permuted_choice_1(key, &permuted_key);

	// חציית המפתח לשניים
	left = (permuted_key >> HALF_KEY_SIZE_BITS) & RIGHT_HALF_KEY_ON; // 28 ביטים שמאליים
	right = permuted_key & RIGHT_HALF_KEY_ON;        // 28 ביטים ימניים

	for (int i = 0; i < 16; i++) {
		//פעמים shifts[i] סיבוב מעגלי שמאלה 
		left_shift(&left, shifts[i]);
		left_shift(&right, shifts[i]);

		// מיזוג הימני והשמאלי למפתח 56 ביטים
		combined_key = ((uint64_t)left << HALF_KEY_SIZE_BITS) | right;

		// יצירת תתי המפתחות
		permuted_choice_2(combined_key, &subkeys[i]);
	}
}

// מרחיב את חצי הימני של הפלט מ32 סיביות ל48 סיביות
static void expansion_function(uint32_t R, uint64_t* expanded_R) {
	int i;
	int E[] = {
		32, 1, 2, 3, 4, 5, 4, 5,
		6, 7, 8, 9, 8, 9, 10, 11,
		12, 13, 12, 13, 14, 15, 16, 17,
		16, 17, 18, 19, 20, 21, 20, 21,
		22, 23, 24, 25, 24, 25, 26, 27,
		28, 29, 28, 29, 30, 31, 32, 1
	};
	*expanded_R = 0;

	for (i = 0;i < SUBKEY_SIZE_BITS;i++) {
		//takes the bit in the E[i] pos in the input and put it in the i pos in the output
		*expanded_R |= ((R >> (E[i] - 1)) & 1) << i;
	}
}

// מבצע החלפות לפי טבלאות הsbox
static void s_box_substitution(uint64_t input, uint32_t* output, int S_BOX[S_BOXES_COUNT][S_BOXES_ROWS][S_BOXES_COLS]) {
	uint8_t six_bits, row, col, s_box_value;
	int i;
	*output = 0;

	for (i = 0; i < 8; i++) {
		// קח 6 ביטים מתחילת הקלט
		six_bits = (input >> (6 * (7 - i))) & 0x3F; // 0x3F first 6 bits is 1

		// חישוב השורה והעמודה
		row = ((six_bits & 0x20) >> 4) | (six_bits & 0x01); // 0x01 first bit is 1, 0x20 the the 6th bit is 1
		//combining the 6th bit and the 1st bit in the right

		col = (six_bits >> 1) & 0x0F; // 0x0F first 4 bits is 1
		//לוקח את הביתים מהשני עד החמישי כולל

		// קח את הערך מה-S-Box
		s_box_value = S_BOX[i][row][col];

		// הוסף את הערך לתוצאה (4 ביטים)
		*output |= (s_box_value << (4 * (7 - i))); // שמור את התוצאה
	}
}

// מבצע חילופים לאחר השימוש בטבלאות SBOXES
static void permutation_function(uint32_t data, uint32_t* permuted_data) {
	int i;
	int P[] = {
		16, 7, 20, 21,
		29, 12, 28, 17,
		1, 15, 23, 26,
		5, 18, 31, 10,
		2, 8, 24, 14,
		32, 27, 3, 9,
		19, 13, 30, 6,
		22, 11, 4, 25
	};
	
	*permuted_data = 0;

	for (i = 0;i < HALF_BLOCK_SIZE_BITS;i++) {
		//takes the bit in the p[i] pos in the input and put it in the i pos in the output
		*permuted_data |= ((data >> (P[i] - 1)) & 1) << i;
	}
}

//פונקצית פיסטל
static void f_function(uint32_t R, uint64_t subkey, uint32_t* f_result, int S_BOX[S_BOXES_COUNT][S_BOXES_ROWS][S_BOXES_COLS]) {
	uint64_t expanded_R;
	uint32_t res;

	expansion_function(R, &expanded_R);
	expanded_R ^= subkey;
	s_box_substitution(expanded_R, &res, S_BOX);
	permutation_function(res, &res);
	*f_result = res;
}

/*פונקציה שמקבלת בלוק בגודל 64 סיביות, מפתח הצפנה בגודל 64 סיביות, מחזירה קלט מוצפן דרך מצביע*/
void DES_encrypt(uint64_t plaintext, uint64_t* ciphertext, uint64_t key) {
	uint32_t L, R, temp;
	uint64_t subkeys[16];
	int i;
	int S_BOX[S_BOXES_COUNT][S_BOXES_ROWS][S_BOXES_COLS];
	srand(key);
	generate_sboxes(S_BOX);

	generate_subkeys(key, subkeys);
	initial_permutation(plaintext, &plaintext);
	split_blocks(plaintext, &L, &R);

	for (i = 0;i < 16;i++) {
		temp = L;
		L = R;
		f_function(R, subkeys[i], &R, S_BOX);
		R ^= temp;
	}
	temp = L;
	L = R;
	R = temp;
	merge_blocks(L, R, &plaintext);
	final_permutation(plaintext, ciphertext);
}

/*פונקציה שמקבלת בלוק מוצפן בגודל 64 סיביות, מפתח הצפנה בגודל 64 סיביות, מחזירה קלט מפוענח דרך מצביע*/
void DES_decrypt(uint64_t ciphertext, uint64_t* plaintext, uint64_t key) {
	uint32_t L, R, temp;
	uint64_t subkeys[16];
	int i;
	int S_BOX[S_BOXES_COUNT][S_BOXES_ROWS][S_BOXES_COLS];
	srand(key);
	generate_sboxes(S_BOX);

	generate_subkeys(key, subkeys);
	initial_permutation(ciphertext, &ciphertext);
	split_blocks(ciphertext, &L, &R);

	for (i = 15;i >= 0;i--) {
		temp = L;
		L = R;
		f_function(R, subkeys[i], &R, S_BOX);
		R ^= temp;
	}
	temp = L;
	L = R;
	R = temp;
	merge_blocks(L, R, &ciphertext);
	final_permutation(ciphertext, plaintext);
}