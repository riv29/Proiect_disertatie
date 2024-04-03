#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "SHA.h"
#include "SHA_Macros.h"

int
SHA1Alg (char* res, char* str) {

	unsigned char input[64];

	FILE* fp = fopen(str, "r");

	fseek(fp, 0, SEEK_END);

	size_t fileSize = ftell(fp), k = 0;

	rewind(fp);

	unsigned int M[16] = {},
		     W[80] = {},
		     tempSHA[5];

	unsigned char flag = 0;

	for (unsigned int i = 0; i < sizeof(SHA1_H) / sizeof(SHA1_H[0]); tempSHA[i] = SHA1_H[i], ++i);

	while (k < fileSize || !fileSize || flag) {
		
		if (k + 64 >= fileSize) {

			memset(M, 0, 16 * sizeof(unsigned int));

			if (!flag) {

				fread(input, sizeof(unsigned char), fileSize - k, fp);

				fclose(fp);

				for (M[0] = input[k % 64] << 24, ++k; k < fileSize; M[(k % 64) / 4] = (M[(k % 64) / 4] | (input[k % 64] << ((3 - ((k % 64) % 4)) * 8))), ++k);

				if (k % 64 != 0)	
					M[(k % 64) / 4] = (M[(k % 64) / 4] | (0x80 << ((3 - ((k % 64) % 4)) * 8)));
			}

			if ((k % 64 < 55 && k % 64 != 0) || flag || !fileSize) {
				if (flag && k % 64 == 0)
					M[0] = 0x80000000;
				M[14] = (fileSize * 8) >> 32;
				M[15] = (fileSize * 8) & 0xffffffff;
				flag = 0;
			} else flag = 1;
		} else {
			fread(input, sizeof(unsigned char), 64, fp);
			for (M[0] = input[k % 64] << 24, ++k; k % 64 != 0; M[(k % 64) / 4] = ((M[(k % 64) / 4] * (k % 64 % 4 > 0)) | (input[k % 64] << ((3 - ((k % 64) % 4)) * 8))), ++k);
		}

		for (unsigned int t = 0; t < 16; W[t] = M[t], ++t);

		for (unsigned int t = 16; t < 80; W[t] = RotateLeft((W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]), 1), ++t);

		unsigned int a = tempSHA[0]
			, b = tempSHA[1]
			, c = tempSHA[2]
			, d = tempSHA[3]
			, e = tempSHA[4]
			, temp;

		for (unsigned int t = 0; t < 80; ++t) {

			if (t >= 0 && t < 20)
				temp = RotateLeft(a, 5) + ((b & c) ^ (~b & d)) + e + SHA1_K[0] + W[t];
		
			if (t >= 20 && t < 40)
				temp = RotateLeft(a, 5) + (b ^ c ^ d) + e + SHA1_K[1] + W[t];
		
			if (t >= 40 && t < 60)
				temp = RotateLeft(a, 5) + ((b & c) ^ (b & d) ^ (c & d)) + e + SHA1_K[2] + W[t];
		
			if (t >= 60 && t < 80)
				temp = RotateLeft(a, 5) + (b ^ c ^ d) + e + SHA1_K[3] + W[t];

			e = d;
			d = c;
			c = RotateLeft(b, 30);
			b = a;
			a = temp;
		}

		tempSHA[0] += a;
		tempSHA[1] += b;
		tempSHA[2] += c;
		tempSHA[3] += d;
		tempSHA[4] += e;

		if (!fileSize) break;
	}

	memcpy(res, tempSHA, 5 * sizeof(unsigned int));

	return 0;
}

int
SHA256Alg (char* res, char* str) {

	unsigned char input[64];

	FILE* fp = fopen(str, "r");

	fseek(fp, 0, SEEK_END);

	size_t fileSize = ftell(fp), k = 0;

	rewind(fp);

	unsigned int M[16] = {},
		     W[64] = {},
		     tempSHA[8];

	unsigned char flag = 0;

	for (unsigned int i = 0; i < sizeof(SHA256_H) / sizeof(SHA256_H[0]); tempSHA[i] = SHA256_H[i], ++i);
	
	while (k < fileSize || !fileSize || flag) {

		if (k + 64 >= fileSize) {

			memset(M, 0, 16 * sizeof(unsigned int));

			if (!flag) {

				fread(input, sizeof(unsigned char), fileSize - k, fp);

				fclose(fp);

				for (M[0] = input[k % 64] << 24, ++k; k < fileSize; M[(k % 64) / 4] = (M[(k % 64) / 4] | (input[k % 64] << ((3 - ((k % 64) % 4)) * 8))), ++k);
		
				if (k % 64 != 0)	
					M[(k % 64) / 4] = (M[(k % 64) / 4] | (0x80 << ((3 - ((k % 64) % 4)) * 8)));
			}

			if ((k % 64 < 55 && k % 64 != 0) || flag || !fileSize) {
				if (flag && k % 64 == 0)
					M[0] = 0x80000000;
				M[14] = (fileSize * 8) >> 32;
				M[15] = (fileSize * 8) & 0xffffffff;
				flag = 0;
			} else flag = 1;

		} else {
			fread(input, sizeof(unsigned char), 64, fp);
			for (M[0] = input[k % 64] << 24, ++k; k % 64 != 0; M[(k % 64) / 4] = ((M[(k % 64) / 4] * (k % 64 % 4 > 0)) | (input[k % 64] << ((3 - ((k % 64) % 4)) * 8))), ++k);
		}

		for (unsigned int t = 0; t < 16; W[t] = M[t], ++t);

		for (unsigned int t = 16; t < 64; W[t] = (sigma1_256(W[t - 2]) + W[t - 7] + sigma0_256(W[t - 15]) + W[t - 16]), ++t);

		unsigned int a = tempSHA[0]
			, b = tempSHA[1]
			, c = tempSHA[2]
			, d = tempSHA[3]
			, e = tempSHA[4]
			, f = tempSHA[5]
			, g = tempSHA[6]
			, h = tempSHA[7]
			, temp1, temp2;

		for (unsigned int t = 0; t < 64; ++t) {

			temp1 = h + sum1_256(e) + ((e & f) ^ (~e & g)) + SHA224_256_K[t] + W[t];
	
			temp2 = sum0_256(a) + ((a & b) ^ (a & c) ^ (b & c));
	
			h = g;
			g = f;
			f = e;
			e = d + temp1;
			d = c;
			c = b;
			b = a;
			a = temp1 + temp2;
		}

		tempSHA[0] += a;
		tempSHA[1] += b;
		tempSHA[2] += c;
		tempSHA[3] += d;
		tempSHA[4] += e;
		tempSHA[5] += f;
		tempSHA[6] += g;
		tempSHA[7] += h;
	}

	memcpy(res, tempSHA, 8 * sizeof(unsigned int));

	return 0;
}

int
_SHA256Alg (char* res, char* str, size_t length) {

	unsigned char input[64];

	size_t k = 0;

	unsigned int M[16] = {},
		     W[64] = {},
		     tempSHA[8];

	unsigned char flag = 0;

	for (unsigned int i = 0; i < sizeof(SHA256_H) / sizeof(SHA256_H[0]); tempSHA[i] = SHA256_H[i], ++i);
	
	while (k < length || !length || flag) {

		if (k + 64 >= length) {

			memset(M, 0, 16 * sizeof(unsigned int));

			if (!flag) {

				memcpy(input, str, length - k);

				for (M[0] = input[k % 64] << 24, ++k; k < length; M[(k % 64) / 4] = (M[(k % 64) / 4] | (input[k % 64] << ((3 - ((k % 64) % 4)) * 8))), ++k);
		
				if (k % 64 != 0)	
					M[(k % 64) / 4] = (M[(k % 64) / 4] | (0x80 << ((3 - ((k % 64) % 4)) * 8)));
			}

			if ((k % 64 < 55 && k % 64 != 0) || flag || !length) {
				if (flag && k % 64 == 0)
					M[0] = 0x80000000;
				M[14] = (length * 8) >> 32;
				M[15] = (length * 8) & 0xffffffff;
				flag = 0;
			} else flag = 1;

		} else {
			memcpy(input, str, 64);
			for (M[0] = input[k % 64] << 24, ++k; k % 64 != 0; M[(k % 64) / 4] = ((M[(k % 64) / 4] * (k % 64 % 4 > 0)) | (input[k % 64] << ((3 - ((k % 64) % 4)) * 8))), ++k);
		}

		for (unsigned int t = 0; t < 16; W[t] = M[t], ++t);

		for (unsigned int t = 16; t < 64; W[t] = (sigma1_256(W[t - 2]) + W[t - 7] + sigma0_256(W[t - 15]) + W[t - 16]), ++t);

		unsigned int a = tempSHA[0]
			, b = tempSHA[1]
			, c = tempSHA[2]
			, d = tempSHA[3]
			, e = tempSHA[4]
			, f = tempSHA[5]
			, g = tempSHA[6]
			, h = tempSHA[7]
			, temp1, temp2;

		for (unsigned int t = 0; t < 64; ++t) {

			temp1 = h + sum1_256(e) + ((e & f) ^ (~e & g)) + SHA224_256_K[t] + W[t];
	
			temp2 = sum0_256(a) + ((a & b) ^ (a & c) ^ (b & c));
	
			h = g;
			g = f;
			f = e;
			e = d + temp1;
			d = c;
			c = b;
			b = a;
			a = temp1 + temp2;
		}

		tempSHA[0] += a;
		tempSHA[1] += b;
		tempSHA[2] += c;
		tempSHA[3] += d;
		tempSHA[4] += e;
		tempSHA[5] += f;
		tempSHA[6] += g;
		tempSHA[7] += h;
	}

	memcpy(res, tempSHA, 8 * sizeof(unsigned int));

	return 0;
}

int
_SHA512Alg (char* res, char* str, size_t length) {
	
	unsigned char input[128];

	size_t k = 0;

	size_t M[16] = {},
		     W[80] = {},
		     tempSHA[8];

	unsigned char flag = 0;

	for (unsigned int i = 0; i < sizeof(SHA512_H) / sizeof(SHA512_H[0]); tempSHA[i] = SHA512_H[i], ++i);
	
	while (k < length || !length || flag) {

		if (k + 128 >= length) {

			memset(M, 0, 16 * sizeof(size_t));

			if (!flag) {

				memcpy(input, str, length - k);

				for (M[0] = (size_t)input[k % 128] << 56, ++k; k < length; M[(k % 128) / 8] = (M[(k % 128) / 8] | ((size_t)input[k % 128] << ((7 - ((k % 128) % 8)) << 3))), ++k);
		
				if (k % 128 != 0)
					M[(k % 128) / 8] = (M[(k % 128) / 8] | ((size_t)0x80 << ((7 - ((k % 128) % 8)) << 3)));
			}

			if ((k % 128 < 111 && k % 128 != 0) || flag || !length) {
				if (flag && k % 128 == 0)
					M[0] = 0x80000000;
				M[14] = (length * 8) >> 32;
				M[15] = (length * 8) & 0xffffffff;
				flag = 0;
			} else flag = 1;
		} else {
			memcpy(input, str, 128);
			for (M[0] = (size_t)input[k % 128] << 56, ++k; k % 128 != 0; M[(k % 128) / 8] = ((M[(k % 128) / 8] * (k % 128 % 8 > 0)) | ((size_t)input[k % 128] << ((7 - ((k % 128) % 8)) << 3))), ++k);
		}

		for (unsigned int t = 0; t < 16; W[t] = M[t], ++t);

		for (unsigned int t = 16; t < 80; W[t] = (sigma1_512(W[t - 2]) + W[t - 7] + sigma0_512(W[t - 15]) + W[t - 16]), ++t);

		size_t a = tempSHA[0],
			b = tempSHA[1],
			c = tempSHA[2],
			d = tempSHA[3],
			e = tempSHA[4],
			f = tempSHA[5],
			g = tempSHA[6],
			h = tempSHA[7],
			temp1, temp2;

		for (unsigned int t = 0; t < 80; ++t) {

			temp1 = h + sum1_512(e) + ((e & f) ^ (~e & g)) + SHA384_512_K[t] + W[t];
	
			temp2 = sum0_512(a) + ((a & b) ^ (a & c) ^ (b & c));
	
			h = g;
			g = f;
			f = e;
			e = d + temp1;
			d = c;
			c = b;
			b = a;
			a = temp1 + temp2;
		}

		tempSHA[0] += a;
		tempSHA[1] += b;
		tempSHA[2] += c;
		tempSHA[3] += d;
		tempSHA[4] += e;
		tempSHA[5] += f;
		tempSHA[6] += g;
		tempSHA[7] += h;
	}

	memcpy(res, tempSHA, 8 * sizeof(size_t));

	return 0;
}

unsigned char*
SHA1Alg_digest (char* str) {
	unsigned char* res = (unsigned char*)calloc(160, 1);
	if (SHA1Alg(res, str)) {
		free(res);
		return NULL;
	}
	return res;
}

unsigned char*
SHA256Alg_digest (char* str) {
	unsigned char* res = (unsigned char*)calloc(256, 1);
	if (SHA256Alg(res, str)) {
		free(res);
		return NULL;
	}
	return res;
}

unsigned char*
_SHA256Alg_digest (char* str, size_t length) {
	unsigned char* res = (unsigned char*)calloc(256, 1);
	if (_SHA256Alg(res, str, length)) {
		free(res);
		return NULL;
	}
	return res;
}

unsigned char*
_SHA512Alg_digest (char* str, size_t length) {
	unsigned char* res = (unsigned char*)calloc(512, 1);
	if (_SHA512Alg(res, str, length)) {
		free(res);
		return NULL;
	}
	return res;
}
