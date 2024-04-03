#ifndef DES_H_
#define DES_H_

unsigned char* DES_encrypt_block(unsigned char[], unsigned char**);
unsigned char* DES_decrypt_block(unsigned char[], unsigned char**);
int DES_encrypt(unsigned char[], unsigned char[], unsigned char**);
int DES_decrypt(unsigned char[], unsigned char[], unsigned char**);
int DESKeySchedule(unsigned char**, unsigned char*);

#endif
