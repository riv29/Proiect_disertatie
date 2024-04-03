#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "SHA.h"
#include "KECCAK_Macros.h"

//5 rc algorithm
unsigned char rc(size_t t){
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

// This doesn't make sense from the NIST doc
//unsigned char* pad_ten_start_one(unsigned int x, unsigned int m) {
//	// m is incremented by 2 because len(M || 01)
//	size_t j = (-(m + 2) - 2) % x;
//	unsigned char* res = (unsigned char*)calloc((j + 4) / 8, 1);
//	res[0] = 0x6; // 01 from len(M || 01) and 10 from pad10*1
//	res[((j + 4) / 8) - 1] = 0x80;
//	return res;
//}

// len = 1600
// nr = 24
void KECCAK_p(char* Message, char* Output, size_t len, size_t nr) {
	
	unsigned char w = WIDTH(len);
	unsigned char dim = (w / 8) + ((w / 8) == 0);

	unsigned char l = 0;
	for (unsigned char i = w; i > 1; i >>= 1, ++l);

       	unsigned char *S = Message,
		      *SPrime = Output;

	// Keccak-p[b, nr] -> 1. Convert S into a state array, A
	// NOTE: might not be neccessary, changing the pointers might help avoid unnecessary memory allocation.
	//for (size_t i = 0; i < 25 * dim; S[i] = Message[i], ++i);

	for (unsigned int ir = 12 + 2 * l - nr; ir < 12 + 2 * l; ++ir) {
		
		//1 Theta algorithm
		for (unsigned char x = 0; x < 5; ++x)
			for (unsigned char y = 0; y < 5; ++y)
				for (unsigned char z = 0; z < w; ++z) {
					MAPPrime(x, y, z) &= ~(1 << (z % 8));
					MAPPrime(x, y, z) |= (THETA(x, y, z) << (z % 8));
				}
		
		SWITCH_MAPS(S, SPrime);
		
		//2 Rho algorithm
		for (unsigned char z = 0; z < w; ++z) {
			MAPPrime(0, 0, z) &= (~(1 << (z % 8)));
			MAPPrime(0, 0, z) |= (MAP(0, 0, z) << (z % 8));
		}

		for (unsigned char t = 0, x = 1, y = 0, temp; t < 24; temp = y, y = (2 * x + 3 * y) % 5, x = temp, ++t)
			for (unsigned char z = 0; z < w; ++z) {
				MAPPrime(x, y, z) &= (~(1 << (z % 8)));
				MAPPrime(x, y, z) |= (RHO(x, y, z) << (z % 8));
			}
		

		SWITCH_MAPS(S, SPrime);
		
		//3 Pi algorithm
		for (unsigned char y = 0; y < 5; ++y)
			for (unsigned char x = 0; x < 5; ++x)
				for (unsigned char z = 0; z < w; ++z) {
					MAPPrime(x, y, z) &= (~(1 << (z % 8)));
					MAPPrime(x, y, z) |= (PI(x, y, z) << (z % 8));
				}
		
		SWITCH_MAPS(S, SPrime);

		//4 Chi algorithm
		for (unsigned char y = 0; y < 5; ++y)
			for (unsigned char x = 0; x < 5; ++x)
				for (unsigned char z = 0; z < w; ++z) {
					MAPPrime(x, y, z) &= (~(1 << (z % 8)));
					MAPPrime(x, y, z) |= (CHI(x, y, z) << (z % 8));
				}

		//6 Iota algorithm
		size_t RC = 0;
		for (size_t j = 0, pow = 1; j <= l; pow <<= 1, ++j) {
			RC &= ~((size_t)1 << (pow - 1));
			RC |= ((size_t)rc(j + 7 * ir) << (pow - 1));
		}

		for (unsigned char z = 0; z < w; ++z) {
			unsigned char temp = ((MAPPrime(0, 0, z) & (1 << (z % 8))) > 0);
			MAPPrime(0, 0, z) &= (~(1 << (z % 8)));
			MAPPrime(0, 0, z) |= (((temp ^ ((RC & ((size_t)1 << z)) > 0)) & 1) << (z % 8));
		}


		SWITCH_MAPS(S, SPrime);
	}
}

unsigned char* SPONGE(char* N, size_t len, size_t d, size_t b, size_t nr) {
	size_t offset = 0, nrOfBytes = len / 8,
	       r = b - 2 * d,
	       block_size = r / 8,
	       n = (len / r) + 1;

	// The whole message will be passed through P according to step 4. in 4 SPONGE CONSTRUCTION
	
	unsigned char	*P = (unsigned char*)calloc(block_size, 1),
		 	*S = (unsigned char*)calloc(b / 8, 1),
			*Output = (unsigned char*)calloc(b / 8, 1);

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
		KECCAK_p(S, Output, b, nr);
	}

	unsigned char* res = (unsigned char*)calloc(d / 8, 1);
	memcpy(res, S, d / 8);
		
	for (unsigned int j = 0; j < d / 8; printf("%x", res[j]), ++j);
	printf("\n");
	
	free(Output);
	free(P);
	free(S);
	return res;
}

unsigned char* SHA3(unsigned char* Message, size_t len, unsigned short digest) {

	if (digest != 224 && digest != 256 && digest != 384 && digest != 512)
		return NULL;
	
	return SPONGE(Message, len * 8, digest, 1600, 24);
}

int main(int argc, const char** argv) {
	if (argc < 3) {
		printf("Arg not valid\n");
		return 1;
	}

	unsigned short digest = 0;

	for (char i = 0; ((char*)argv[1])[i] != '\0'; digest = digest * 10 + (((char*)argv[1])[i] - '0'), ++i);

	FILE* fp = fopen((char*)argv[2], "r");
	fseek(fp, 0, SEEK_END);
	size_t file_size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	char* content = (char*)malloc(file_size);
	fread(content, 1, file_size, fp);
	printf("%lu\n", file_size);
	fclose(fp);

	unsigned char* res = SHA3(content, file_size, digest);

	if (res == NULL) {
		printf("SHA3 failed\n");
		return 1;
	}

	return 0;
}
