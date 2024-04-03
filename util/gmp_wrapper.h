#ifndef GMP_WRAPPER_H_
#define GMP_WRAPPER_H_
#include <gmp.h>

#define ALLOC_MPZ_PTR(nbr) do { \
	if ((nbr) == NULL) {\
		if (((nbr) = (mpz_t*)malloc(sizeof(mpz_t))) == NULL)\
			return 1; \
		mpz_init(*(nbr));\
	} \
} while (0)

#define FREE_MPZ_PTR(nbr) do { \
	if ((nbr) != NULL) {\
		mpz_clear(*(nbr)); \
		free((nbr)); \
		(nbr) = NULL; \
	} \
} while (0)

#define STR_TO_MPZ_T(dest, src, len) do { \
	mpz_set_ui((dest), 0); \
	for (size_t i = 0; i < len; ++i) { \
		mpz_mul_ui((dest), (dest), 0x100); \
		mpz_add_ui((dest), (dest), ((src)[i] & 0xff)); \
	} \
} while (0)

#define MPZ_T_TO_STR(dest, src, len) do { \
	len = mpz_sizeinbase(src, 2); \
	len = len / 8 + ((len % 8) > 0);\
	dest = (char*)malloc(len); \
	mpz_t r; \
	mpz_init(r); \
	for (size_t ind = len - 1; (ind + 1) > 0;  --ind) { \
		mpz_mod_ui(r, src, 0x100); \
		dest[ind] = (char)(mpz_get_ui(r) & 0xff); \
		mpz_tdiv_q_ui(src, src, 0x100); \
	} \
	mpz_clear(r); \
} while (0)

#endif
