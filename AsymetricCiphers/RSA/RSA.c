#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../ASN/ASN.h"
#include "../Key_Gen/GenPrimes.h"
#include "RSA.h"

typedef struct gmp_str_buf{
	unsigned char* buf;
	size_t buf_len;
	struct gmp_str_buf* next;
}gmp_str_buf;

int ExtractPublicKey(char** exp, char** mod, char* path) {
	asn1elem* elem = NULL;

	if (*exp != NULL) {
		free(*exp);
		*exp = NULL;
	}

	if (*mod != NULL) {
		free(*mod);
		*mod = NULL;
	}

	if (!Extract_public_key(&elem, path)) {
		*mod = (char*)malloc((elem->key_modulus.length * 2) + 1);
		for (size_t i = 0; i < elem->key_modulus.length; ++i) {
			char high_nibble = (elem->key_modulus.text[i] >> 4) & 0xf;
			char low_nibble = elem->key_modulus.text[i] & 0xf;
			(*mod)[i * 2] = ('0' + high_nibble) * (high_nibble < 10) + ('a' + (high_nibble - 10))  * (high_nibble >= 10);
			(*mod)[i * 2 + 1] = ('0' + low_nibble) * (low_nibble < 10) + ('a' + (low_nibble - 10))  * (low_nibble >= 10);
		}
		(*mod)[elem->key_modulus.length * 2] = '\0';
		*exp = (char*)malloc((elem->public_key_exp.length * 2) + 1);
		for (size_t i = 0; i < elem->public_key_exp.length; ++i) {
			char high_nibble = (elem->public_key_exp.text[i] >> 4) & 0xf;
			char low_nibble = elem->public_key_exp.text[i] & 0xf;
			(*exp)[i * 2] = ('0' + high_nibble) * (high_nibble < 10) + ('a' + (high_nibble - 10))  * (high_nibble >= 10);
			(*exp)[i * 2 + 1] = ('0' + low_nibble) * (low_nibble < 10) + ('a' + (low_nibble - 10))  * (low_nibble >= 10);
		}
		(*exp)[elem->public_key_exp.length * 2] = '\0';
		destroy_asn1elem(&elem);
	}

	return 0;
}

int ExtractPrivateKey(char** exp, char** mod, char* path) {
	
	asn1elem* elem = NULL;
	
	if (*exp != NULL) {
		free(*exp);
		*exp = NULL;
	}

	if (*mod != NULL) {
		free(*mod);
		*mod = NULL;
	}

	if (!Extract_private_key(&elem, path)) {
		*mod = (char*)malloc((elem->key_modulus.length * 2) + 1);
		for (size_t i = 0; i < elem->key_modulus.length; ++i) {
			char high_nibble = (elem->key_modulus.text[i] >> 4) & 0xf;
			char low_nibble = elem->key_modulus.text[i] & 0xf;
			(*mod)[i * 2] = ('0' + high_nibble) * (high_nibble < 10) + ('a' + (high_nibble - 10))  * (high_nibble >= 10);
			(*mod)[i * 2 + 1] = ('0' + low_nibble) * (low_nibble < 10) + ('a' + (low_nibble - 10))  * (low_nibble >= 10);
		}
		(*mod)[elem->key_modulus.length * 2] = '\0';
		*exp = (char*)malloc(elem->private_key_exp.length * 2);
		for (size_t i = 0; i < elem->private_key_exp.length; ++i) {
			char high_nibble = (elem->private_key_exp.text[i] >> 4) & 0xf;
			char low_nibble = elem->private_key_exp.text[i] & 0xf;
			(*exp)[i * 2] = ('0' + high_nibble) * (high_nibble < 10) + ('a' + (high_nibble - 10))  * (high_nibble >= 10);
			(*exp)[i * 2 + 1] = ('0' + low_nibble) * (low_nibble < 10) + ('a' + (low_nibble - 10))  * (low_nibble >= 10);
		}
		(*exp)[elem->private_key_exp.length * 2] = '\0';
		destroy_asn1elem(&elem);
	}

	return 0;
}

int CreateKeyFiles(RSA_Ctx ctx, const char* path) {
	
	asn1elem* elem = (asn1elem*)calloc(1, sizeof(asn1elem));

	// Put N to asn1elem.key_modulus field
	MPZ_T_TO_STR(elem->key_modulus.text, ctx.N, elem->key_modulus.length);

	// Put e to asn1elem.public_key_exp
	MPZ_T_TO_STR(elem->public_key_exp.text, ctx.e, elem->public_key_exp.length);

	// Put d to asn1elem.private_key_exp
	MPZ_T_TO_STR(elem->private_key_exp.text, ctx.d, elem->private_key_exp.length);

	// Put p to asn1elem.p
	MPZ_T_TO_STR(elem->p.text, *(ctx.primes.p), elem->p.length);

	// Put d to asn1elem.q
	MPZ_T_TO_STR(elem->q.text, *(ctx.primes.q), elem->q.length);

	// Put iqmp to asn1elem.iqmp
	MPZ_T_TO_STR(elem->iqmp.text, ctx.iqmp, elem->iqmp.length);

	// TODO: Might be worth looking into different type of keys other than ssh
	// Works for now ...
	elem->key_type.text = (char*)malloc(7);
	for (int i = 0; i < 7; elem->key_type.text[i] = "ssh-rsa"[i], ++i);
	elem->key_type.length = 7;

	// TODO: If encryption support is added this needs to be more dynamic
	elem->aes_version.text = (char*)malloc(4);
	for (int i = 0; i < 4; elem->aes_version.text[i] = "none"[i], ++i);
	elem->aes_version.length = 4;

	// Either bcrypt or none
	elem->crypt_type.text = (char*)malloc(4);
	for (int i = 0; i < 4; elem->crypt_type.text[i] = "none"[i], ++i);
	elem->crypt_type.length = 4;

	// TODO: Might be worth to look into generating multiple keys in one ASN file
	elem->number_of_keys = 1;

	Create_public_key(elem, path);
	Create_private_key(elem, path);

	destroy_asn1elem(&elem);
}

// Generate a value for E
// An odd number between 2^17 and 2^256
void GenerateE(mpz_t rez, mpz_t p, mpz_t q) {
	mpz_t rand_base, rand_limit, gcd_rez;

	mpz_inits(rand_base, rand_limit, gcd_rez, NULL);

	gmp_randstate_t randstate;
	gmp_randinit_default(randstate);

	mpz_set_ui(rand_base, 2);
	mpz_pow_ui(rand_base, rand_base, 17);

	mpz_set_ui(rand_limit, 2);
	mpz_pow_ui(rand_limit, rand_limit, 256);

	mpz_sub(rand_limit, rand_limit, rand_base);

	for (;;) {

		mpz_urandomm(rez, randstate, rand_limit);

		mpz_add(rez, rez, rand_base);

		mpz_setbit(rez, 0);

		mpz_gcd(gcd_rez, rez, p);

		if (mpz_cmp_ui(gcd_rez, 1) > 0)
			continue;

		mpz_gcd(gcd_rez, rez, q);

		if (!mpz_cmp_ui(gcd_rez, 1))
			break;
	}

	gmp_randclear(randstate);
	mpz_clears(rand_base, rand_limit, gcd_rez, NULL);
}

void Fermat(mpz_t rez, mpz_t msg, mpz_t mpz_power, mpz_t mpz_N) {

	mpz_set_ui(rez, 1);
	mpz_t power, N, mod_rop;

	mpz_inits(power, N, mod_rop, NULL);

	mpz_set(power, mpz_power);
	
	mpz_set(N, mpz_N);

	while (mpz_cmp_ui(power, 0)) {
		mpz_mod_ui(mod_rop, power, 2);
		if (mpz_cmp_ui(mod_rop, 0)) {
			mpz_mul(rez, rez, msg);
			mpz_mod(rez, rez, N);
		}
		mpz_mul(msg, msg, msg);
		mpz_mod(msg, msg, N);
		mpz_tdiv_q_ui(power, power, 2);
	}
	
	mpz_clears(power, N, mod_rop, NULL);
}

RSA_Ctx CreateRSACtx() {
	RSA_Ctx rez;
	init_keypair_ctx(&(rez.primes));
	mpz_inits(rez.N, rez.e, rez.d, rez.iqmp, NULL);
	return rez;
}

void DestroyRSACtx(RSA_Ctx* item) {
	mpz_clears(item->N, item->e, item->d, item->iqmp, NULL);
	free_keypair_ctx(&(item->primes));
}

int GenerateKeys(const char* path) {

	RSA_Ctx ctx = CreateRSACtx();
	
	mpz_t p1, q1, O;

	mpz_inits(p1, q1, O, NULL);

	generate_primes(&(ctx.primes), RSA_2048_224);

	mpz_mul(ctx.N, *(ctx.primes.p), *(ctx.primes.q));

	mpz_sub_ui(p1, *(ctx.primes.p), 1);
	mpz_sub_ui(q1, *(ctx.primes.q), 1);

	mpz_mul(O, p1, q1);

	GenerateE(ctx.e, p1, q1);

	mpz_invert(ctx.d, ctx.e, O);
	
	mpz_clears(p1, q1, O, NULL);
	
	mpz_invert(ctx.iqmp, *(ctx.primes.q), *(ctx.primes.p));

	CreateKeyFiles(ctx, path);

	DestroyRSACtx(&ctx);

	return 0;
}

int Encrypt(unsigned char** res, unsigned char* publicFile, unsigned char* msg) {

	char *N = NULL, *e = NULL;

	ExtractPublicKey(&e, &N, publicFile);

	mpz_t mpz_N, mpz_e, mpz_enc, mpz_msg;

	mpz_inits(mpz_N, mpz_e, mpz_enc, mpz_msg, NULL);

	mpz_set_str(mpz_N, N, 16);

	mpz_set_str(mpz_e, e, 16);

	mpz_set_ui(mpz_msg, 0);

	gmp_str_buf *buff = NULL, *encrypted_block;

	size_t res_len = 0, len;
	
	for (unsigned int i = 0; i < strlen(msg); ++i) {
		mpz_mul_ui(mpz_msg, mpz_msg, 0x100);
		mpz_add_ui(mpz_msg, mpz_msg, (unsigned char)msg[i]);
		if (mpz_cmp(mpz_msg, mpz_N) > 0) {
			encrypted_block = (gmp_str_buf*)malloc(sizeof(gmp_str_buf));
			mpz_tdiv_q_ui(mpz_msg, mpz_msg, 0x100);
			Fermat(mpz_enc, mpz_msg, mpz_e, mpz_N);
			mpz_set_ui(mpz_msg, (unsigned char)msg[i]);
			len = mpz_sizeinbase(mpz_enc, 16);
			encrypted_block->buf = (unsigned char*)malloc(len);
			res_len += len + 1;
			encrypted_block->buf_len = len;
			encrypted_block->next = buff;
			gmp_snprintf(encrypted_block->buf, len + 1, "%Zx", mpz_enc);
			buff = encrypted_block;
		}
	}
	
	encrypted_block = (gmp_str_buf*)malloc(sizeof(gmp_str_buf));
	Fermat(mpz_enc, mpz_msg, mpz_e, mpz_N);
	len = mpz_sizeinbase(mpz_enc, 16);
	encrypted_block->buf = (unsigned char*)malloc(len + 1);
	res_len += len + 1;
	encrypted_block->buf_len = len;
	encrypted_block->next = buff;
	gmp_snprintf(encrypted_block->buf, len + 1, "%Zx", mpz_enc);
	buff = encrypted_block;
	
	if (*res)
		free(*res);

	*res = (unsigned char*)malloc(res_len + 1);

	for (size_t offset = 0; buff != NULL;) {
		offset += buff->buf_len + 1;
		strncpy((*res) + res_len - offset, buff->buf, buff->buf_len);
		(*res)[res_len - offset + buff->buf_len] = 'x';
		free(buff->buf);
		gmp_str_buf* q = buff;
		buff = buff->next;
		free(q);
		q = NULL;
	}

	(*res)[res_len - 1] = 'x';
	(*res)[res_len] = '\0';

	if (buff != NULL)
		free(buff);

	mpz_clears(mpz_N, mpz_e, mpz_enc, mpz_msg, NULL);

	return 0;
}

int Decrypt(unsigned char** res, unsigned char* privateFile, unsigned char* cipher) {

	char *N = NULL, *d = NULL;

	ExtractPrivateKey(&d, &N, privateFile);

	mpz_t mpz_N, mpz_d, mpz_dec, mpz_cipher;

	mpz_inits(mpz_N, mpz_d, mpz_dec, mpz_cipher, NULL);

	mpz_set_str(mpz_N, N, 16);

	mpz_set_str(mpz_d, d, 16);

	unsigned char* tempCipher = cipher;

	unsigned char* temp = (unsigned char*)malloc(strlen(cipher) * sizeof(unsigned char));

	unsigned long int offset = 0;

	unsigned char* aux = strchr(tempCipher, 'x');

	while (aux) {

		aux[0] = '\0';

		mpz_set_str(mpz_cipher, tempCipher, 16);
	
		Fermat(mpz_dec, mpz_cipher, mpz_d, mpz_N);
		size_t length = mpz_sizeinbase(mpz_dec, 16);

		mpz_get_str(temp + offset, 16, mpz_dec);

		offset += length;
		tempCipher = aux + 1;
		aux = strchr(tempCipher, 'x');
	}

	temp[offset] = '\0';

	if (*res)
		free(*res);

	*res = (unsigned char*)malloc((offset / 2) + 1);

	for (unsigned long int i = 0, k = 0; i < offset / 2; ++i, ++k) {
		unsigned char high_nibble = temp[i * 2],
				low_nibble = temp[i * 2 + 1];
		high_nibble = 
			(high_nibble >= '0' && high_nibble <= '9') * (high_nibble - '0') + 
			(high_nibble >= 'a' && high_nibble <= 'f') * (high_nibble - 'a' + 10) + 
			(high_nibble >= 'A' && high_nibble <= 'F') * (high_nibble - 'A' + 10);
		low_nibble = 
			(low_nibble >= '0' && low_nibble <= '9') * (low_nibble - '0') + 
			(low_nibble >= 'a' && low_nibble <= 'f') * (low_nibble - 'a' + 10) + 
			(low_nibble >= 'A' && low_nibble <= 'F') * (low_nibble - 'A' + 10);
		(*res)[i] = ((high_nibble << 4) & 0xf0) | (low_nibble & 0xf);
	}

	(*res)[offset / 2] = '\0';

	free(temp);

	mpz_clears(mpz_N, mpz_d, mpz_dec, mpz_cipher, NULL);

	return 0;
}
