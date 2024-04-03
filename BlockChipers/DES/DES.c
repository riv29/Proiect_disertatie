#include <stdlib.h>
#include <string.h>
#include "DES.h"

unsigned char K[] = {
	56, 48, 40, 32, 24, 16, 8,
	0, 57, 49, 41, 33, 25, 17,
	9, 1, 58, 50, 42, 34, 26,
	18, 10, 2, 58, 51, 43, 35,
	62, 54, 46, 38, 30, 22, 14,
	6, 61, 53, 45, 37, 29, 21,
	20, 12, 4, 27, 19, 11, 3
};

unsigned char KPlus[]= {
	1, 1, 2, 2, 2, 2, 2, 2,
       	1, 2, 2, 2, 2, 2, 2, 1
};

unsigned char PC_2[] = {
	13, 16, 10, 23, 0, 4,
	2, 27, 14, 5, 20, 9,
	22, 18, 11, 3, 25, 7,
	15, 6, 26, 19, 12, 1,
	40, 51, 30, 36, 46, 54,
	29, 39, 20, 44, 32, 47,
	43, 48, 38, 55, 33, 52,
	45, 41, 49, 35, 28, 31
};

unsigned char IP[] = {
	57, 49, 41, 33, 25, 17, 9, 1,
	59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5,
	63, 55, 47, 39, 31, 23, 15, 7,
	56, 48, 40, 32, 24, 16, 8, 0,
	58, 50, 42, 34, 26, 18, 10, 2,
	60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6
};

unsigned char SelTable[] = {
	31, 0, 1, 2, 3, 4,
	3, 4, 5, 6, 7, 8,
	7, 8, 9, 10, 11, 12,
	11, 12, 13, 14, 15, 16,
	15, 16, 17, 18, 19, 20,
	19, 20, 21, 22, 23, 24,
	23, 24, 25, 26, 27, 28,
	27, 28, 29, 30, 31, 0
};

unsigned char S[8][64] = {
	{
		14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
		0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
		4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
		15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
	},
	{
		15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
		3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
		0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
		13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
	},
	{
		10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
		13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
		13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
		1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
	},
	{
		7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
		13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
		10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
		3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
	},
	{
		2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
		14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
		4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
		11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
	},
	{
		12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
		10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
		9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
		4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
	},
	{
		4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
		13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
		1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
		6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
	},
	{
		13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
		1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
		7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
		2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
	}
};

unsigned char PF[] = {
	15, 6, 19, 20,
	28, 11, 27, 16,
	0, 14, 22, 25,
	4, 17, 30, 9,
	1, 7, 23, 13,
	31, 26, 2, 8,
	18, 12, 29, 5,
	21, 10, 3, 24
};

unsigned char InversePerm[] = {
	39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30,
	37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28,
	35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26,
	33, 1, 41, 9, 49, 17, 57, 25,
	32, 0, 40, 8, 48, 16, 56, 24
};

int DESKeySchedule(unsigned char** Keys, unsigned char* key) {
	
	unsigned char keyBytes[64];

	for (int i = 0, k = 0; i < 8; ++i)
		for (int index = 0x80; index != 0; index >>= 1, ++k)
			keyBytes[k] = ((key[i] & index) > 0);

	// TODO: This should be changed from i * 48 to i * 6 once DES is updated
	for (size_t i = 0; i < 16; Keys[i] = Keys[0] + i * 48, ++i);

	unsigned char PC1[56];
	
	for (int i = 0; i < 56; ++i)
		PC1[i] = keyBytes[K[i]];
	
	unsigned char C[17][28], D[17][28];
	
	memcpy(C[0], PC1, 28);
	memcpy(D[0], PC1 + 28, 28);

	for (int i = 1; i < 17; ++i) {
		memcpy(C[i], C[i - 1] + KPlus[i - 1], 28 - KPlus[i - 1]);
		memcpy(C[i] + 28 - KPlus[i - 1], C[i - 1], KPlus[i - 1]);
		memcpy(D[i], D[i - 1] + KPlus[i - 1], 28 - KPlus[i - 1]);
		memcpy(D[i] + 28 - KPlus[i - 1], D[i - 1], KPlus[i - 1]);
	}

	unsigned char temp[56];

	for (int i = 0; i < 16; ++i) {
		memcpy(temp, C[i + 1], 28);
		memcpy(temp + 28, D[i + 1], 28);
		for (int j = 0; j < 48; ++j)
			Keys[i][j] = temp[PC_2[j]];
	}
	
	return 0;
}

unsigned char* DES_encrypt_block(unsigned char plaintext[], unsigned char** Keys) {

	unsigned char* res = (unsigned char*)calloc(8, sizeof(unsigned char));

	DES_encrypt(res, plaintext, Keys);

	return res;
}

int DES_encrypt(unsigned char res[], unsigned char plaintext[], unsigned char** Keys) {

	unsigned char block[64];

	for (int i = 0, k = 0; i < 8; ++i)
		for (int index = 0x80; index != 0; index >>= 1, ++k)
			block[k] = ((plaintext[i] & index) > 0);	

	unsigned char L[32], R[32];
	
	memcpy(L, block, 32 * sizeof(unsigned char));
	memcpy(R, block + 32, 32 * sizeof(unsigned char));
	
	unsigned char Perm[64];

	for (int i = 0; i < 64; ++i)
		Perm[i] = block[IP[i]];

	unsigned char Left[17][32], Right[17][32];

	memcpy(Left[0], Perm, 32 * sizeof(unsigned char));
	memcpy(Right[0], Perm + 32, 32 * sizeof(unsigned char));

	for (int i = 1; i < 17; ++i) {
		
		unsigned char B[8][6], FRez[32];

		memcpy(Left[i], Right[i - 1], 32);

		for (int j = 0; j < 48; ++j)
			B[j / 6][j % 6] = (Right[i - 1][SelTable[j]] ^ Keys[i - 1][j]);

		for (int j = 0; j < 8; ++j) {

			unsigned int line = ((B[j][0] << 1) | B[j][5]);
			unsigned int col = ((B[j][1] << 3) | (B[j][2] << 2) | (B[j][3] << 1) | B[j][4]);
			
			unsigned int pos = line * 16 + col;

			FRez[j * 4 + 3] = ((S[j][pos] & 0x08) > 0);
			FRez[j * 4 + 2] = ((S[j][pos] & 0x04) > 0);
			FRez[j * 4 + 1] = ((S[j][pos] & 0x02) > 0);
			FRez[j * 4 + 0] = ((S[j][pos] & 0x01) > 0);
		}
	
		for (int j = 0; j < 32; ++j)
			Right[i][j] = (Left[i - 1][j] ^ FRez[PF[j]]);
	}

	memcpy(Perm, Right[16], 32);
	memcpy(Perm + 32, Left[16], 32);

	unsigned char Rez[64];

	for (int i = 0; i < 64; ++i)
		Rez[i] = Perm[InversePerm[i]];

	for (int i = 0; i < 8; ++i)
		for (int j = 0; j < 8; ++j)
			res[i] |= (Rez[i * 8 + j] << (7 - j));
}

unsigned char* DES_decrypt_block (unsigned char plaintext[], unsigned char** Keys) {

	unsigned char* res = (unsigned char*)calloc(8, sizeof(unsigned char));

	DES_decrypt(res, plaintext, Keys);

	return res;
}

int DES_decrypt(unsigned char res[], unsigned char plaintext[], unsigned char** Keys) {

	unsigned char block[64];

	for (int i = 0, k = 0; i < 8; ++i)
		for (int index = 0x80; index != 0; index >>= 1, ++k)
			block[k] = ((plaintext[i] & index) > 0);

	unsigned char L[32], R[32];
	
	memcpy(L, block, 32 * sizeof(unsigned char));
	memcpy(R, block + 32, 32 * sizeof(unsigned char));
	
	unsigned char Perm[64];

	for (int i = 0; i < 64; ++i)
		Perm[i] = block[IP[i]];

	unsigned char Left[17][32], Right[17][32];

	memcpy(Left[0], Perm, 32 * sizeof(unsigned char));
	memcpy(Right[0], Perm + 32, 32 * sizeof(unsigned char));

	for (int i = 1; i < 17; ++i) {
		
		unsigned char B[8][6], FRez[32];

		memcpy(Left[i], Right[i - 1], 32);

		for (int j = 0; j < 48; ++j)
			B[j / 6][j % 6] = (Right[i - 1][SelTable[j]] ^ Keys[15 - i + 1][j]);

		for (int j = 0; j < 8; ++j) {

			unsigned int line = ((B[j][0] << 1) | B[j][5]);
			unsigned int col = ((B[j][1] << 3) | (B[j][2] << 2) | (B[j][3] << 1) | B[j][4]);
			
			unsigned int pos = line * 16 + col;

			FRez[j * 4 + 3] = ((S[j][pos] & 0x08) > 0);
			FRez[j * 4 + 2] = ((S[j][pos] & 0x04) > 0);
			FRez[j * 4 + 1] = ((S[j][pos] & 0x02) > 0);
			FRez[j * 4 + 0] = ((S[j][pos] & 0x01) > 0);
		}
	
		for (int j = 0; j < 32; ++j)
			Right[i][j] = (Left[i - 1][j] ^ FRez[PF[j]]);
	}

	memcpy(Perm, Right[16], 32);
	memcpy(Perm + 32, Left[16], 32);

	unsigned char Rez[64];

	for (int i = 0; i < 64; ++i)
		Rez[i] = Perm[InversePerm[i]];

	for (int i = 0; i < 8; ++i)
		for (int j = 0; j < 8; ++j)
			res[i] |= (Rez[i * 8 + j] << (7 - j));	
}
