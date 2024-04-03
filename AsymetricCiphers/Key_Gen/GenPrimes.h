#ifndef GENPRIMES_H_
#define GENPRIMES_H_
#include "../util/gmp_wrapper.h"
#include "../util/util_types.h"

typedef enum {
	None,
	RSA_1024,
	DSA_1024,
	RSA_2048_224,
	DSA_2048_224,
       	RSA_2048_256,	
	DSA_2048_256,
	RSA_3072,
	DSA_3072
} Test_Type;

typedef int (*hash_function)(char*, char*, size_t);

typedef struct {
	mpz_t *p, *q;
} Key_pair;

extern hash_function hash_method;

uint8_t init_keypair_ctx(Key_pair*);
uint8_t set_hash_function(hash_function);
uint8_t free_keypair_ctx(Key_pair*);
uint8_t generate_primes(Key_pair*, Test_Type);

#endif
