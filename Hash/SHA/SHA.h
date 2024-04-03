#ifndef SHA_H_
#define SHA_H_

unsigned char* SHA1Alg_digest (char*);
unsigned char* SHA256Alg_digest (char*);
unsigned char* _SHA256Alg_digest (char*, size_t);
unsigned char* _SHA512Alg_digest (char*, size_t);
unsigned char* SHA3_224_digest(char*, size_t);
unsigned char* SHA3_256_digest(char*, size_t);
unsigned char* SHA3_384_digest(char*, size_t);
unsigned char* SHA3_512_digest(char*, size_t);

int SHA1Alg (char*, char*);
int SHA256Alg (char*, char*);
int _SHA256Alg (char*, char*, size_t);
int _SHA512Alg (char*, char*, size_t);
int KECCAK(char*, char*, size_t);
int SHA3_224(char*, char*, size_t);
int SHA3_256(char*, char*, size_t);
int SHA3_384(char*, char*, size_t);
int SHA3_512(char*, char*, size_t);

#endif
