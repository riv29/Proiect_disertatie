#ifndef RSA_H_
#define RSA_H_
#include <gmp.h>

typedef struct {
	Key_pair primes;
	mpz_t N;
	mpz_t e, d;
	mpz_t iqmp;
} RSA_Ctx;

void Fermat(mpz_t, mpz_t, mpz_t, mpz_t);
int GenerateKeys(const char*);
int Encrypt(unsigned char**, unsigned char*, unsigned char*);
int Decrypt(unsigned char**, unsigned char*, unsigned char*);

#endif
