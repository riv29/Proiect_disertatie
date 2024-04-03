#ifndef __DSA__H__
#define __DSA__H__
#include "../Key_Gen/GenPrimes.h"
#include "../util/util_types.h"

typedef struct {
	Key_pair* keys;
	mpz_t *g, *k;
} dsa_ctx;

#endif
