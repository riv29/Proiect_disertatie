#ifndef AES_H_
#define AES_H_

#define INDEX(index) (((index & 0xf0) >> 4) * 16 + (index & 0x0f))

typedef enum {
	X02,
	X03,
	X0E, 
	X0B, 
	X0D,
	X09,
	X01
} MixType;

typedef enum {
	AES128,
	AES192,
	AES256,
	None
} AES_Type;

unsigned char* AES_decrypt_block(unsigned char[], unsigned char**);
unsigned char* AES_encrypt_block(unsigned char[], unsigned char**);
int AES_encrypt(unsigned char[], unsigned char[], unsigned char**);
int AES_decrypt(unsigned char[], unsigned char[], unsigned char**);
//int AddKey(unsigned char[], unsigned char[]);
//int InvMixColumns(unsigned char[]);
//int MixColumns(unsigned char[]);
//int InvShiftRows(unsigned char[]);
//int ShiftRows(unsigned char[]);
//int InvSubstituteBytes(unsigned char[]);
//int SubstituteBytes(unsigned char[]);
int AESKeySchedule(unsigned char**, unsigned char*);
extern AES_Type AES_type;

#endif
