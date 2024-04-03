#ifndef ASN_H_
#define ASN_H_

typedef struct {
	char* text;
	unsigned int length;
} asn1field;

typedef struct {
       	asn1field crypt_type;
	asn1field salt;
	asn1field key_type, key_modulus; // N
	asn1field aes_version;
	asn1field public_key_exp, // e
		  private_key_exp; // d
	asn1field iqmp, p, q;
	asn1field comment;
       	char *ssh_version;
	unsigned int number_of_rounds,
		     number_of_keys;
} asn1elem;

void destroy_asn1elem(asn1elem**);
int Extract_public_key(asn1elem**, const char*);
int Create_public_key(asn1elem*, const char*);
int Extract_private_key(asn1elem**, const char*);
int Create_private_key(asn1elem*, const char*);

#endif
