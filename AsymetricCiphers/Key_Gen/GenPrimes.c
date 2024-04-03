#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "GenPrimes.h"
#include "../SHA/SHA.h"

#define MAX_DIGEST_SIZE 64
#define MAX_SEEDLEN 64
#define SUCCESS 0
#define FAILED 1
// Private global variables for generating primes logic
static int16_t random_fp = -1;
static size_t seed_len;
static Test_Type cipher;
static uint8_t digest_size,
		     hash_result[MAX_DIGEST_SIZE],
		     domain_seed[MAX_SEEDLEN],
		     offset_seed[MAX_SEEDLEN],
		     seed_handler[MAX_SEEDLEN];

hash_function hash_method = NULL;

uint8_t
init_keypair_ctx(Key_pair* ctx) {

	Key_pair* key_handler = ctx;

	ALLOC_MPZ_PTR(key_handler->p);
	ALLOC_MPZ_PTR(key_handler->q);

	return 0;
}

uint8_t
free_keypair_ctx(Key_pair* ctx) {
	
	Key_pair* key_handler = ctx;

	FREE_MPZ_PTR(key_handler->p);
	FREE_MPZ_PTR(key_handler->q);

	return 0;
}

uint8_t
set_hash_function(hash_function method) {

	hash_method = method;

	// Digest size in bytes
	digest_size = 0 +
		(hash_method == SHA3_224) * 28 +
		(hash_method == _SHA256Alg || hash_method == SHA3_256) * 32 +
		(hash_method == SHA3_384) * 48 +
		(hash_method == _SHA512Alg || hash_method == SHA3_512) * 64;

	seed_len = digest_size;

	return !digest_size;
}

// Apendix 1.1.2 prime p and q generation
// Apendix 1.1.3 validation of p and q

uint8_t
get_rand_bytes(uint8_t* seed, size_t len) {

	return !(random_fp > 0 && read(random_fp, seed, len) > 0);
}

// Rabin Miller prime probability check (Apendix C.3.1)
uint8_t
rabin_miller_check(mpz_t nbr) {

	int16_t res = SUCCESS;
	size_t a = 1;

	uint8_t iterations;

	switch (cipher) {
		case RSA_1024:
		case DSA_1024:
		case RSA_2048_224:
		case DSA_2048_224:
		case RSA_2048_256:
		case DSA_2048_256: iterations = 64; break;
		case RSA_3072:
		case DSA_3072: iterations = 128; break;
		default: return 1;
	}

	mpz_t temp, m, b, w, w3, g, z, x;
	gmp_randstate_t random_state;
	
	mpz_inits(temp, m, b, w, w3, g, z, x, NULL);
	gmp_randinit_default(random_state);

	mpz_set(w, nbr);
	mpz_sub_ui(w, w, 1);
	
	mpz_set(w3, nbr);
	mpz_sub_ui(w3, w3, 3);

	// Step 1 Start with a = 1 and keep shifting it to the left until the first bit of temp.
	for (a=1; mpz_tstbit(w, a) == 0; ++a);

	// Step 2 m = (w - 1) / 2 ^ a
	mpz_tdiv_q_2exp(m, w, a);

	for (uint8_t idx = 0; idx < a; mpz_mul_ui(m, m, 2), ++idx);	

	size_t bit_len = mpz_sizeinbase(nbr, 2);
	
	// Value for iterations must be selected from tables shown in C.{1,2,3}
	for(size_t i = 0; i < iterations; ++i) {
		// Step 4.1
		mpz_urandomm(b, random_state, w3);
		mpz_add_ui(b, b, 2);

		// Step 4.3
		mpz_gcd(g, b, nbr);

		// Step 4.4
		if (mpz_cmp_ui(g, 1) != 0)
			goto err; // PROVABLY COMPOSITE WITH FACTOR Step 4.4 

		// Step 4.5
		mpz_powm(z, b, m, nbr);

		if (mpz_cmp_ui(z, 1) == 0 || mpz_cmp(z, w) == 0)
			goto repeat; // Step 4.6

		// Step 4.7
		for (size_t j = 1; j < a; ++j) {
			// Step 4.7.1
			mpz_set(x, z);

			// Step 4.7.2
			mpz_powm_ui(z, x, 2, nbr);

			// Step 4.7.3
			if (!mpz_cmp(z, w))
				goto repeat; // PROVABLY COMPOSITE WITH FACTOR Step 4.7.3

			// Step 4.7.4
			if (!mpz_cmp_ui(z, 1))
				goto jump_ahead;
		}

		// Step 4.8
		mpz_set(x, z);

		// Step 4.9
		mpz_powm_ui(z, x, 2, nbr);

		// Step 4.10
		if (!mpz_cmp_ui(z, 1))
			goto jump_ahead;

		// Step 4.11
		mpz_set(x, z);
jump_ahead:

		// Step 4.12
		mpz_sub_ui(x, x, 1);
		mpz_gcd(g, x, nbr);

		// Step 4.13
		if (mpz_cmp_ui(g, 1) > 0)
			goto err; // PROVABLY COMPOSITE WITH FACTOR

		goto err;
repeat:
	}
goto finish; // Success
err:
	res = FAILED;
finish:
	mpz_clears(temp, m, b, w, w3, g, z, x, NULL);
	gmp_randclear(random_state);
	return res; // PROVABLY COMPOSITE AND NOT A POWER OF PRIME
}

// Apendix A 1.1.3
uint8_t
check_prime(mpz_t nbr) {

	

	return 0;
}

uint8_t
generate_q(Key_pair* ctx, size_t N) {
	
	uint8_t* U;
	
	for (;;) {
		// A 1.1.2 Step(5)
		if (get_rand_bytes(domain_seed, seed_len)) return 1;	

		// 1.1.2 Step(6) : U = hash_method % 2 ^ (N - 1)
		hash_method(hash_result, domain_seed, seed_len);
		
		// q_size = N >> 3;
		size_t hash_size = N >> 3; // Transform N, which is represented in bits into byte size

		// Take the least significant bits of hash_result
		// Check openssl/crypto/ffc/ffc_params_generate.c (line 341)
		U = hash_result;
		if (digest_size > hash_size)
			U += digest_size - hash_size;

		// IGNORE: This might not be necessary
		//if (digest_size < hash_size)
		//	memset(U + digest_size, 0, hash_size - digest_size);

		// 1.1.2 Step(7)
		// Check openssl::ffc_params_generate.c for details (line 350)
		U[0] |= 0x80;
		U[hash_size - 1] |= 0x01;

		// Actual assignment of q
		STR_TO_MPZ_T(*(ctx->q), U, hash_size);

		// 1.1.2 Step(8) and Step(9)
		if (rabin_miller_check(*(ctx->q)) == SUCCESS)
			break;
	}

	return 0;
}

uint8_t
generate_p(Key_pair* ctx, size_t L) {
	uint8_t res = FAILED;
	
	// A 1.1.2 Step(3)
	// This field is only necessary for p generation
	int16_t n = (L / (digest_size << 3)) - 1;

	// W is a very big boy :)
	mpz_t W, X, c, q_mod, tmp, L_power, bit_mask;
	mpz_inits(W, X, c, q_mod, tmp, L_power, bit_mask, NULL);

	// Preparation for A 1.1.2 Step (11.3)
	// These values never change withing the loop in Step (11)
	mpz_set_ui(L_power, 2);
	mpz_pow_ui(L_power, L_power, L - 1); // L_power is 2^(L-1)
	mpz_set(bit_mask, L_power);
	mpz_sub_ui(bit_mask, bit_mask, 1); // bit_mask is a mask: 2^(L-1) - 1
	mpz_mul_ui(q_mod, *(ctx->q), 2); // 2*q used in A 1.1.3 Step (11.4)

	memcpy(offset_seed, domain_seed, seed_len);
	for (size_t counter = 0; counter < 4 * L - 1; ++counter) {
		// Reset seed_handler to the seed with additional offset
		memcpy(seed_handler, offset_seed, seed_len);
		mpz_set_ui(W, 0);
		// A 1.1.2 Step (11.1) and Step (11.2)
		for (size_t j = 0; j <= n; ++j) {
			// Build seed_handler for Vj using the seed_handler from Vj-1
			// This repeteadly increments the seed_handler to build the message for Vj
			for (size_t k = seed_len - 1; (k + 1) >= 1; --k) {
				++seed_handler[k];
				if (seed_handler[k] != 0x0)
					break;
			}

			// Compute Vj
			hash_method(hash_result, seed_handler, seed_len);

			// Map Vj to a temporary mpz
			STR_TO_MPZ_T(tmp, hash_result, digest_size);
			
			// Shift tmp to the left with digest_size bytes and append the temporary mpz
			mpz_mul_2exp(tmp, tmp, (digest_size << 3) * j);
			mpz_add(W, W, tmp);
		}

		// A 1.1.2 Step (11.3) 
		mpz_and(W, W, bit_mask); // Apply mask on W to make this "0 < W < 2 ^ (L - 1)" valid
		mpz_add(X, W, L_power);

		// A 1.1.2 Step (11.4)
		mpz_tdiv_r(c, X, q_mod);

		// A 1.1.2 Step (11.5)
		mpz_set(*(ctx->p), X);
		mpz_sub(*(ctx->p), *(ctx->p), c);
		mpz_add_ui(*(ctx->p), *(ctx->p), 1);

		// A 1.1.2 Step (11.6)
		if (mpz_cmp(*(ctx->p), L_power) < 0) {
			// This should be a placeholder for domain_parameter_seed + offset
			// Add n + 1 to offset and repeat
			for (uint8_t idx = 0; idx < n + 1; ++idx) {
				for (size_t k = seed_len - 1; (k + 1) >= 1; --k) {
					++offset_seed[k];
					if (offset_seed[k] != 0x0)
						break;
				}
			}
			continue;
		}

		// A 1.1.2 Step (11.7)
		if (rabin_miller_check(*(ctx->p)) == SUCCESS) {
			res = SUCCESS;
			goto finish;
		}

		for (size_t k = seed_len - 1; (k + 1) >= 1; --k) {
			++offset_seed[k];
			if (offset_seed[k] != 0x0)
				break;
		}
	}

	res = FAILED;
finish:
	mpz_clears(W, X, c, q_mod, tmp, L_power, bit_mask, NULL);

	return res;
}

uint8_t
generate_primes(Key_pair* ctx, Test_Type key_type) {

	uint16_t N, L;

	random_fp = open("/dev/urandom", O_RDONLY);

	if (random_fp < 0) return 1;

	// A 1.1.2 Step(1)
	switch(key_type) {
		case RSA_1024:
		case DSA_1024: L = 1024; N = 160; break;
		case RSA_2048_224: 
		case DSA_2048_224: L = 2048; N = 256; break; 
		case RSA_2048_256: 
		case DSA_2048_256: L = 2048; N = 256; break; 
		case RSA_3072: 
		case DSA_3072: L = 3072; N = 256; break;
		default: return 1;
	}

	cipher = key_type;
	
	// FIXME: Currently hardcoded to use SHA_256; Replace it
	set_hash_function(_SHA256Alg);

	// A 1.1.2 Step(2) seed_len (in bits) is smaller than N
	if ((seed_len << 3) < N) return 1;
	
	do {
		while (generate_q(ctx, N) == FAILED);
	} while (generate_p(ctx, L) == FAILED);

	close(random_fp);
	random_fp = -1;

	return 0;
}
