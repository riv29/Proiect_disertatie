#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "SHA.h"

#define SWITCH_MAPS(a, b) \
	do { \
		size_t* aux = (a); \
		(a) = (b); \
		(b) = aux; \
	} while(0)

#define MAP(x, y) (S[(y) * 5 + (x)])
#define MAPPrime(x, y) (SPrime[(y) * 5 + (x)])
#define ROTL(x, amm) (((x) << (amm)) | ((x) >> (64 - (amm))))
#define C(x) (MAP(x, 0) ^ MAP(x, 1) ^ MAP(x, 2) ^ MAP(x, 3) ^ MAP(x, 4))
#define D(x) (C((x + 4) % 5) ^ ROTL(C((x + 1) % 5), 1))
#define THETA(x, y) (MAP(x, y) ^ d)
#define RHO(x, y) (ROTL(MAP(x, y), (t + 1) * (t + 2) / 2))
#define PI(x, y) (MAP((x + 3 * y) % 5, x))
#define CHI(x, y) (MAP(x, y) ^ ((~MAP((x + 1) % 5, y)) & MAP((x + 2) % 5, y)))

//5 rc algorithm
static unsigned char
rc(size_t t){
	if (!(t % 255)) // If t mod 255 = 0, return 1
		return 1;
	unsigned char R = 0x80; // Let R = 0b1000_0000
	for (unsigned char i = 0; i < (t % 255); ++i) {
		unsigned char val = R & 0x01;
		R = (R >> 1) & 0x7f; // R = 0 || R
		R ^= (val << 7); // R[0] = R[0] ^ R[8]
		R ^= (val << 3); // R[4] = R[4] ^ R[8]
		R ^= (val << 2); // R[5] = R[5] ^ R[8]
		R ^= (val << 1); // R[6] = R[6] ^ R[8]
	}
	return ((R & 0x80) > 1); // Retrun R[0]
}	

static void
SHA3_KECCAK(char* Message) {
	
       	size_t Map[25] = {0}, MapPrime[25] = {0}, *S = Map, *SPrime = MapPrime;

	// Keccak-p[b, nr] -> 1. Convert S into a state array, A
	// NOTE: might not be neccessary, changing the pointers might help avoid unnecessary memory allocation.
	for (size_t i = 0; i < 200; S[i / 8] |= (((size_t)Message[i] & 0xff) << (8 * (i % 8))), ++i);

	for (unsigned int ir = 0; ir < 24; ++ir) {
		
		//1 Theta algorithm
		for (unsigned char x = 0; x < 5; ++x) {
			size_t d = D(x);
			for (unsigned char y = 0; y < 5; ++y)
				MAPPrime(x, y) = THETA(x, y);
		}

		SWITCH_MAPS(S, SPrime);
		
		//2 Rho algorithm
		MAPPrime(0, 0) = MAP(0, 0);

		for (unsigned char t = 0, x = 1, y = 0, temp; t < 24; temp = y, y = (2 * x + 3 * y) % 5, x = temp, ++t)
			MAPPrime(x, y) = RHO(x, y);
		

		SWITCH_MAPS(S, SPrime);
		
		//3 Pi algorithm
		for (unsigned char y = 0; y < 5; ++y)
			for (unsigned char x = 0; x < 5; ++x)
				MAPPrime(x, y) = PI(x, y);
		
		
		SWITCH_MAPS(S, SPrime);

		//4 Chi algorithm
		for (unsigned char y = 0; y < 5; ++y)
			for (unsigned char x = 0; x < 5; ++x)
				MAPPrime(x, y) = CHI(x, y);

		//6 Iota algorithm
		size_t RC = 0;
		for (size_t j = 0, pow = 1; j <= 6; pow <<= 1, ++j) {
			RC &= ~((size_t)1 << (pow - 1));
			RC |= ((size_t)rc(j + 7 * ir) << (pow - 1));
		}

		MAPPrime(0, 0) ^= RC;

		SWITCH_MAPS(S, SPrime);
	}

	for (size_t i = 0; i < 200; Message[i] = ((S[i / 8] >> (8 * (i % 8))) & 0xff), ++i);
}

static int
SPONGE(unsigned char* res, char* N, size_t len, size_t d) {
	size_t offset = 0, nrOfBytes = len / 8,
	       r = 1600 - 2 * d,
	       block_size = r / 8,
	       n = (len / r) + 1;

	// The whole message will be passed through P according to step 4. in 4 SPONGE CONSTRUCTION
	
	unsigned char	P[200] = {0},
		 	S[200] = {0},
			Output[200] = {0};

	for (size_t i = 0; i < n; ++i, offset += block_size) {
		if (offset + block_size < nrOfBytes)
			memcpy(P, N + offset, block_size);
		else {
			memcpy(P, N + offset, (nrOfBytes - offset) * (offset < nrOfBytes));
			for (size_t j = (nrOfBytes - offset) * (offset < nrOfBytes); j < block_size; P[j] = 0x0, ++j);

			P[nrOfBytes - offset] = 0x6;
			P[block_size - 1] = 0x80;
		}
		for (unsigned int j = 0; j < block_size; S[j] ^= P[j], ++j);
		SHA3_KECCAK(S);
	}

	memcpy(res, S, d / 8);

	return 0;
}

int
SHA3_224(char* res, char* Message, size_t len) {
	return SPONGE(res, Message, len * 8, 224);
}

int
SHA3_256(char* res, char* Message, size_t len) {
	return SPONGE(res, Message, len * 8, 256);
}

int
SHA3_384(char* res, char* Message, size_t len) {
	return SPONGE(res, Message, len * 8, 384);
}

int
SHA3_512(char* res, char* Message, size_t len) {
	return SPONGE(res, Message, len * 8, 512);
}

unsigned char*
SHA3_224_digest(char* Message, size_t len) {
	unsigned char* res = (unsigned char*)calloc(224, 1);
	if (SPONGE(res, Message, len * 8, 224)) {
		free(res);
		return NULL;
	}
	return res;
}

unsigned char*
SHA3_256_digest(char* Message, size_t len) {
	unsigned char* res = (unsigned char*)calloc(256, 1);
	if (SPONGE(res, Message, len * 8, 256)) {
		free(res);
		return NULL;
	}
	return res;
}

unsigned char*
SHA3_384_digest(char* Message, size_t len) {
	unsigned char* res = (unsigned char*)calloc(384, 1);
	if (SPONGE(res, Message, len * 8, 384)) {
		free(res);
		return NULL;
	}
	return res;
}

unsigned char*
SHA3_512_digest(char* Message, size_t len) {
	unsigned char* res = (unsigned char*)calloc(512, 1);
	if (SPONGE(res, Message, len * 8, 512)) {
		free(res);
		return NULL;
	}
	return res;
}
