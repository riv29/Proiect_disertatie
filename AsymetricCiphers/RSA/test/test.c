#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmp.h>
#include "../../DSA/DSA.h"
#include "../../ASN/ASN.h"
#include "../../SHA/SHA.h"
#include "../RSA.h"
#include "../../Key_Gen/GenPrimes.h"

//int rabin_miller_test(int argc, const char** argv) {
//
//	if (argc < 1)
//		return 1;
//
//	asn1elem* holder = NULL;
//	Extract_private_key(&holder, (char*)argv[1]);
//
//	mpz_t temp;
//	mpz_init(temp);
//	mpz_set_ui(temp, 0);
//	for(size_t i = 0; i < holder->p_len; mpz_mul_ui(temp, temp, 0x100), mpz_add_ui(temp, temp, holder->p[i] & 0xff), ++i);
//
//	for (size_t i = 0; i < 1000000; ++i) {
//		if (!rabin_miller_check(temp)) {
//			mpz_out_str(stdout, 10, temp);
//			printf("\n");
//		}
//		mpz_add_ui(temp, temp, 1);
//	}
//	for(size_t i = 0; i < holder->p_len; mpz_mul_ui(temp, temp, 0x100), mpz_add_ui(temp, temp, holder->p[i] & 0xff), ++i);
//
//	for (size_t i = 0; i < 1000000; ++i) {
//		if (!rabin_miller_check(temp)) {
//			mpz_out_str(stdout, 10, temp);
//			printf("\n");
//		}
//		mpz_add_ui(temp, temp, 1);
//	}
//	mpz_clear(temp);
//
//	return 0;
//}

//int key_generation_test (int argc, const char** argv) {
//
//	Key_pair* key_pair = NULL;
//
//	init_keypair_ctx(&key_pair);
//
//	set_hash_function(SHA3_256);
//
//	if (generate_primes(key_pair, RSA_1024))
//		return 1;
//
//	printf("p = ");
//	mpz_out_str(stdout, 16, *(key_pair->p));
//	printf("\n");
//
//	printf("q = ");
//	mpz_out_str(stdout, 16, *(key_pair->q));
//	printf("\n\n");
//	
//	printf("p = ");
//	mpz_out_str(stdout, 10, *(key_pair->p));
//	printf("\n");
//
//	printf("q = ");
//	mpz_out_str(stdout, 10, *(key_pair->q));
//	printf("\n");
//
//	free_keypair_ctx(&key_pair);
//
//	return 0;
//}

int asn_pub_create_test(int argc, const char** argv) {

	if (argc < 2)
		return 1;

	asn1elem* elem = NULL;

	char* path = (char*)argv[1];

	char* public_path = (char*)malloc(strlen(path) + 5);

	strcpy(public_path, path);

	strcpy(public_path + strlen(path), ".pub");
	
	Extract_public_key(&elem, public_path);
	
	Create_public_key(elem, "res.pub");

	destroy_asn1elem(&elem);

	elem = NULL;

	Extract_private_key(&elem, path);

	Create_private_key(elem, "res");
	
	destroy_asn1elem(&elem);

	free(public_path);

	return 0;
}

int generate_keys(int argc, const char** argv) {

	if (argc < 2) {
		printf("Not enough arguments!!!\n");
		return 1;
	}

	GenerateKeys(argv[1]);

	return 0;
}

int test_rsa_encrpytion(int argc, const char** argv) {

	if (argc < 3) {
		printf("Not enough arguments!!!\n");
		return 1;
	}

	char* pub_key = (char*)calloc(strlen(argv[1]) + 5, 1);

	memcpy(pub_key, argv[1], strlen(argv[1]));

	memcpy(pub_key + strlen(argv[1]), ".pub", 4);

	unsigned char* enc = NULL, *dec = NULL;

	Encrypt(&enc, pub_key, (unsigned char*)argv[2]);

	FILE* fp = fopen("enc.txt", "w");

	fprintf(fp, "%s", enc);

	fclose(fp);

	Decrypt(&dec, (unsigned char*)argv[1], enc);

	fp = fopen("dec.txt", "w");

	fprintf(fp, "%s", dec);

	fclose(fp);

	free(enc);

	free(dec);

	return 0;
}

int test_rsa_signature(int argc, const char** argv) {

	if (argc < 3) {
		printf("Not enough arguments!!!\n");
		return 1;
	}

	char* pub_key = (char*)calloc(strlen(argv[1]) + 5, 1);

	memcpy(pub_key, argv[1], strlen(argv[1]));

	memcpy(pub_key + strlen(argv[1]), ".pub", 4);

	unsigned char* enc = NULL, *dec = NULL;

	Decrypt(&enc, (unsigned char*)argv[1], (unsigned char*)argv[2]);

	FILE* fp = fopen("enc.txt", "w");

	fprintf(fp, "%s", enc);

	fclose(fp);

	Encrypt(&dec, pub_key, enc);

	fp = fopen("dec.txt", "w");

	fprintf(fp, "%s", dec);

	fclose(fp);

	free(enc);

	free(dec);

	return 0;
}

int main(int argc, const char** argv) {

	generate_keys(argc, argv);

	test_rsa_encrpytion(argc, argv);

	//test_rsa_signature(argc, argv);

	return 0;
}
