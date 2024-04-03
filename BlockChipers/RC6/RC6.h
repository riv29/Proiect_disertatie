#ifndef RC6_H_
#define RC6_H_

#define rotateLeft(num, amount) ((num << (amount % (8 * sizeof(unsigned int)))) | (num >> ((8 * sizeof(unsigned int)) - (amount % (8 * sizeof(unsigned int))))))
#define rotateRight(num, amount) ((num >> (amount % (8 * sizeof(unsigned int)))) | (num << ((8 * sizeof(unsigned int)) - (amount % (8 * sizeof(unsigned int))))))
#define BSWAP(number) (((number & 0xff) << 24) | (((number >> 8) & 0xff) << 16) | (((number >> 16) & 0xff) << 8) | ((number >> 24) & 0xff))

#define MAX(a, b) ((a > b) * a + (a <= b) * b)
#define Pw 0xB7E15163
#define Qw 0x9E3779B9

typedef struct {
	unsigned int w, b, r;
}RC6Config;

extern RC6Config Config;

int RC6KeySchedule(unsigned char**, unsigned char*);

unsigned char* RC6_encrypt_block(unsigned char[], unsigned char**);
unsigned char* RC6_decrypt_block(unsigned char[], unsigned char**);

int RC6_encrypt(unsigned char[], unsigned char[], unsigned char**);
int RC6_decrypt(unsigned char[], unsigned char[], unsigned char**);

void populateWord(unsigned char*, unsigned int*, unsigned char, unsigned int);

char* printBytes(unsigned char*, unsigned int);

char* printRegister(unsigned int, unsigned int);

#endif
