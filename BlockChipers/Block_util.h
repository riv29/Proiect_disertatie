#ifndef BLOCK_UTIL_H_
#define BLOCK_UTIL_H_
#include "../util/util_types.h"

typedef enum {
	AES_128,
	AES_192,
	AES_256,
	DES,
	TRIPLE_DES,
	RC6_128,
	RC6_192,
	RC6_256,
	ARIA,
	BLOWFISH,
	NO_CIPHER
} Block_cipher;

typedef enum {
	ECB,
        CBC,
        OFB,
        CFB,
        CTR
} Block_opmode;

typedef enum {
	BytePadding,
	X9_23,
	PKCS_5_7
} Padding_type;

typedef struct Block_ctx {
	Block_cipher type;
	unsigned long int Counter;
	uint8_t blockSize;
	uint8_t Nonce[32], IV[32];
	uint8_t* Input;
	bytes_t keys[16];
       	int (*keySchedule)(bytes_t*, bytes_t);
	
	bytes_t (*encrypt_block_method)(uint8_t[], bytes_t*);
	bytes_t (*decrypt_block_method)(uint8_t[], bytes_t*);
	int (*encrypt_method)(uint8_t[], uint8_t[], bytes_t*);
	int (*decrypt_method)(uint8_t[], uint8_t[], bytes_t*);

	int (*encrypt)(struct Block_ctx*, bytes_t, bytes_t);
	int (*decrypt)(struct Block_ctx*, bytes_t, bytes_t);
	bytes_t (*encrypt_block)(struct Block_ctx*, bytes_t);
	bytes_t (*decrypt_block)(struct Block_ctx*, bytes_t);

	void (*add_padding)(bytes_t, uint8_t, uint8_t);
	uint8_t (*remove_padding)(bytes_t, uint8_t);

} Block_ctx;

Block_ctx* GetContext();
void ClearContext();

#endif
