#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "RC6.h"

RC6Config Config;

void populateWord(unsigned char* src, unsigned int* dest, unsigned char offset, unsigned int length) {
	*dest = 0;
	for (int i = 0, len = length / 4; i < len; ++i)
		*dest |= (src[i + offset * len] << (8 * (3 - i)));
}

char* printBytes(unsigned char* src, unsigned int len) {
	
	unsigned int count = 0;
	
	char buff[50];
	
	for(int i = 0; i < len; ++i) {
		sprintf(buff, "%x ", src[i]);
 		count += strlen(buff);
	}
	
	unsigned char* res = (unsigned char*)malloc(count);

	res[0] = '\0';

	for (int i = 0; i < len; ++i) {
		sprintf(buff, "%x ", src[i]);
		strcpy(res + strlen(res), buff);
	}

	return res;
}

char* printRegister(unsigned int src, unsigned int len) {
	unsigned char* temp = (unsigned char*)(&src);
	return printBytes(temp, len);
}

int RC6KeySchedule(unsigned char** Keys, unsigned char* key) {

	unsigned int* res = (unsigned int*)(*Keys);

	// This line is deprecated, can ignore it for now
	//unsigned int* res = (unsigned int*)malloc((2 * Config.r + 4) * sizeof(unsigned int));

	res[0] = Pw;

	for (int i = 1; i < 2 * Config.r + 4; ++i)
		res[i] = res[i - 1] + Qw;

	unsigned int L[4];

	populateWord(key, &(L[0]), 3, Config.b);
	populateWord(key, &(L[1]), 2, Config.b);
	populateWord(key, &(L[2]), 1, Config.b);
	populateWord(key, &(L[3]), 0, Config.b);

	//printf("%x %x %x %x\n\n", L[0], L[1], L[2], L[3]);

	for (unsigned int s = 0,
		       	i = 0, j = 0, A = 0, B = 0,
		       	v = 3 * MAX(2 * Config.r + 4, 4);
		       	s < v;
		       	++s, 
			i = (i + 1) % (2 * Config.r + 4), 
			j = (j + 1) % 4) {
		res[i] = rotateLeft(res[i] + A + B, 3);
		A = res[i];
		L[j] = rotateLeft(L[j] + A + B, (unsigned int)(A + B));
		B = L[j];
	//	printf("A=%x : B=%x\n", A, B);
	}

	unsigned char* temp = (unsigned char*)res;

       	Keys = &temp;

	return 0;
}

unsigned char* RC6_encrypt_block(unsigned char text[], unsigned char** SubKey) {
	
	unsigned char *res = (unsigned char*)malloc(8 * sizeof(unsigned int));

	RC6_encrypt(res, text, SubKey);

	return res;
}

int RC6_encrypt(unsigned char res[], unsigned char text[], unsigned char** SubKey) {

	unsigned int* S = (unsigned int*)(*SubKey);

	unsigned int A, B, C, D;
	
	populateWord(text, &A, 0, Config.b);

	populateWord(text, &B, 1, Config.b);

	populateWord(text, &C, 2, Config.b);

	populateWord(text, &D, 3, Config.b);

	unsigned int shift_amm = 0;

	for(; (1 << shift_amm) != Config.w; ++shift_amm);

	unsigned int i, t, u;
	B += S[0];
	D += S[1];
	for (i = 1; i <= Config.r; ++i) {
		t = rotateLeft(B * (2 * B + 1), shift_amm);
		u = rotateLeft(D * (2 * D + 1), shift_amm);
		A = rotateLeft((A ^ t), u) + S[2 * i];
		C = rotateLeft((C ^ u), t) + S[2 * i + 1];
		t = A; A = B; B = C; C = D; D = t;
	}
	A += S[2 * (i - 1) + 2];
	C += S[2 * (i - 1) + 3];

	A = BSWAP(A);
	B = BSWAP(B);
	C = BSWAP(C);
	D = BSWAP(D);

	memcpy(res + 0 * sizeof(unsigned int), &A, 4);
	memcpy(res + 1 * sizeof(unsigned int), &B, 4);
	memcpy(res + 2 * sizeof(unsigned int), &C, 4);
	memcpy(res + 3 * sizeof(unsigned int), &D, 4);
}

unsigned char* RC6_decrypt_block(unsigned char ciphertext[], unsigned char** SubKey) {

	unsigned char *res = (unsigned char*)malloc(8 * sizeof(unsigned int));

	RC6_decrypt(res, ciphertext, SubKey);

	return res;
}

int RC6_decrypt(unsigned char res[], unsigned char ciphertext[], unsigned char** SubKey) {
	
	unsigned int* S = (unsigned int*)(*SubKey);
	
	unsigned int A, B, C, D;

	populateWord(ciphertext, &A, 0, Config.b);
	populateWord(ciphertext, &B, 1, Config.b);
	populateWord(ciphertext, &C, 2, Config.b);
	populateWord(ciphertext, &D, 3, Config.b);

	unsigned int shift_amm = 0;

	for(; (1 << shift_amm) != Config.w; ++shift_amm);

	unsigned int i, t, u;
	C -= S[2 * Config.r + 3];
	A -= S[2 * Config.r + 2];
	for (i = Config.r; i > 0 ; --i) {
		t = D; D = C; C = B; B = A; A = t;
		t = rotateLeft(B * (2 * B + 1), shift_amm);
		u = rotateLeft(D * (2 * D + 1), shift_amm);
		A = (rotateRight(A - S[2 * i], u) ^ t);
		C = (rotateRight(C - S[2 * i + 1], t) ^ u);
	}
	D -= S[1];
	B -= S[0];

	A = BSWAP(A);
	B = BSWAP(B);
	C = BSWAP(C);
	D = BSWAP(D);

	memcpy(res + 0 * sizeof(unsigned int), &A, 4);
	memcpy(res + 1 * sizeof(unsigned int), &B, 4);
	memcpy(res + 2 * sizeof(unsigned int), &C, 4);
	memcpy(res + 3 * sizeof(unsigned int), &D, 4);
}
