#include "Modes.h"

//TODO: Delete this
#include <stdio.h>

#define MEMCPY(dest, src, len) for (unsigned int i = 0; i < (len); (dest)[i] = (src)[i], ++i)

static unsigned char _Input[32];

int EncryptECB(Block_ctx* ctx, bytes_t ciphertext, bytes_t plaintext) {
	ctx->encrypt_method(ciphertext, plaintext, ctx->keys);
	return 0;
}

int DecryptECB(Block_ctx* ctx, bytes_t plaintext, bytes_t ciphertext) {
	ctx->decrypt_method(plaintext, ciphertext, ctx->keys);
	return 0;
}

int EncryptCBC(Block_ctx* ctx, bytes_t ciphertext, bytes_t plaintext) {
	
	if (!ctx->Input) {
		ctx->Input = _Input;
		MEMCPY(ctx->Input, ctx->IV, ctx->blockSize * sizeof(uint8_t));
	}

	for (unsigned int i = 0; i < ctx->blockSize; ++i)
		ctx->Input[i] ^= plaintext[i];

	ctx->encrypt_method(ciphertext, ctx->Input, ctx->keys);
	
	MEMCPY(ctx->Input, ciphertext, ctx->blockSize * sizeof(uint8_t));

	return 0;
}

int DecryptCBC(Block_ctx* ctx, bytes_t plaintext, bytes_t ciphertext) {
	
	ctx->decrypt_method(plaintext, ciphertext, ctx->keys);

	if (!ctx->Input) {
		ctx->Input = _Input;
		MEMCPY(ctx->Input, ciphertext, ctx->blockSize * sizeof(uint8_t));
		for (unsigned int i = 0; i < ctx->blockSize; ++i)
			plaintext[i] ^= ctx->IV[i];
	} else {
		for (unsigned int i = 0; i < ctx->blockSize; ++i)
			plaintext[i] ^= ctx->Input[i];
		MEMCPY(ctx->Input, ciphertext, ctx->blockSize * sizeof(uint8_t));
	}
	
	return 0;
}

int EncryptOFB(Block_ctx* ctx, bytes_t ciphertext, bytes_t plaintext) {
	
	if (!ctx->Input) {
		ctx->Input = _Input;
		MEMCPY(ctx->Input, ctx->IV, ctx->blockSize * sizeof(uint8_t));
	}

	ctx->encrypt_method(ciphertext, ctx->Input, ctx->keys);
	
	MEMCPY(ctx->Input, ciphertext, ctx->blockSize * sizeof(uint8_t));

	for (unsigned int i = 0; i < ctx->blockSize; ++i)
		ciphertext[i] ^= plaintext[i];
	
	return 0;
}

int DecryptOFB(Block_ctx* ctx, bytes_t plaintext, bytes_t ciphertext) {
	
	if (!ctx->Input) {
		ctx->Input = _Input;
		MEMCPY(ctx->Input, ctx->IV, ctx->blockSize * sizeof(uint8_t));
	}

	ctx->encrypt_method(plaintext, ctx->Input, ctx->keys);
	
	MEMCPY(ctx->Input, plaintext, ctx->blockSize * sizeof(uint8_t));

	for (unsigned int i = 0; i < ctx->blockSize; ++i)
		plaintext[i] ^= ciphertext[i];
	
	return 0;
}


int EncryptCFB(Block_ctx* ctx, bytes_t ciphertext, bytes_t plaintext) {
	
	if (!ctx->Input) {
		ctx->Input = _Input;
		MEMCPY(ctx->Input, ctx->IV, ctx->blockSize * sizeof(uint8_t));
	}
	ctx->encrypt_method(ciphertext, ctx->Input, ctx->keys);
	
	for (unsigned int i = 0; i < ctx->blockSize; ++i)
		ciphertext[i] ^= plaintext[i];

	MEMCPY(ctx->Input, ciphertext, ctx->blockSize * sizeof(uint8_t));
	
	return 0;
}

int DecryptCFB(Block_ctx* ctx, bytes_t plaintext, bytes_t ciphertext) {
	
	if (!ctx->Input) {
		ctx->Input = _Input;
		MEMCPY(ctx->Input, ctx->IV, ctx->blockSize * sizeof(uint8_t));
	}
	ctx->encrypt_method(plaintext, ctx->Input, ctx->keys);

	for (unsigned int i = 0; i < ctx->blockSize; ++i)
		plaintext[i] ^= ciphertext[i];

	MEMCPY(ctx->Input, ciphertext, ctx->blockSize * sizeof(uint8_t));
	
	return 0;
}

int EncryptCTR(Block_ctx* ctx, bytes_t ciphertext, bytes_t plaintext) {

	if (!ctx->Input)
		ctx->Input = _Input;

	unsigned int* temp = (unsigned int*)ctx->Nonce;

	*temp += ctx->Counter;

	bytes_t SumRes = (bytes_t)temp;

	for (unsigned int i = 0; i < ctx->blockSize; ++i)
		ctx->Input[i] = SumRes[i];

	++ctx->Counter;

	ctx->encrypt_method(ciphertext, ctx->Input, ctx->keys);

	for (unsigned int i = 0; i < ctx->blockSize; ++i)
		ciphertext[i] ^= plaintext[i];
	
	return 0;
} 

int DecryptCTR(Block_ctx* ctx, bytes_t plaintext, bytes_t ciphertext) {
	
	if (!ctx->Input)
		ctx->Input = _Input;

	unsigned int* temp = (unsigned int*)ctx->Nonce;

	*temp += ctx->Counter;

	bytes_t SumRes = (bytes_t)temp;

	for (unsigned int i = 0; i < ctx->blockSize; ++i)
		ctx->Input[i] = SumRes[i];

	++ctx->Counter;

	ctx->encrypt_method(plaintext, ctx->Input, ctx->keys);

	for (unsigned int i = 0; i < ctx->blockSize; ++i)
		plaintext[i] ^= ciphertext[i];
	
	return 0;
} 

bytes_t EncryptECB_block(Block_ctx* ctx, bytes_t plaintext) {
	return ctx->encrypt_block_method(plaintext, ctx->keys);
}

bytes_t DecryptECB_block(Block_ctx* ctx, bytes_t ciphertext) {
	return ctx->decrypt_block_method(ciphertext, ctx->keys);
}

bytes_t EncryptCBC_block(Block_ctx* ctx, bytes_t plaintext) {

	bytes_t ciphertext = 0;

	if (!ctx->Input) {
		ctx->Input = _Input;
		MEMCPY(ctx->Input, ctx->IV, ctx->blockSize * sizeof(uint8_t));
	}

	for (unsigned int i = 0; i < ctx->blockSize; ++i)
		ctx->Input[i] ^= plaintext[i];

	ciphertext = ctx->encrypt_block_method(ctx->Input, ctx->keys);
	
	MEMCPY(ctx->Input, ciphertext, ctx->blockSize * sizeof(uint8_t));
	
	return ciphertext;
}

bytes_t DecryptCBC_block(Block_ctx* ctx, bytes_t ciphertext) {
	
	bytes_t plaintext = 0;

	plaintext = ctx->decrypt_block_method(ctx->Input, ctx->keys);

	if (!ctx->Input) {
		ctx->Input = _Input;
		MEMCPY(ctx->Input, ciphertext, ctx->blockSize * sizeof(uint8_t));
		for (unsigned int i = 0; i < ctx->blockSize; ++i)
			plaintext[i] ^= ctx->IV[i];
	} else {
		for (unsigned int i = 0; i < ctx->blockSize; ++i)
			plaintext[i] ^= ctx->Input[i];
		MEMCPY(ctx->Input, ciphertext, ctx->blockSize * sizeof(uint8_t));
	}
	
	return plaintext;
}

bytes_t EncryptOFB_block(Block_ctx* ctx, bytes_t plaintext) {
	
	bytes_t ciphertext = 0;

	if (!ctx->Input) {
		ctx->Input = _Input;
		MEMCPY(ctx->Input, ctx->IV, ctx->blockSize * sizeof(uint8_t));
	}

	ciphertext = ctx->encrypt_block_method(ctx->Input, ctx->keys);
	
	MEMCPY(ctx->Input, ciphertext, ctx->blockSize * sizeof(uint8_t));

	for (unsigned int i = 0; i < ctx->blockSize; ++i)
		ciphertext[i] ^= plaintext[i];

	return ciphertext;
}

bytes_t DecryptOFB_block(Block_ctx* ctx, bytes_t ciphertext) {
	
	bytes_t plaintext = 0;

	if (!ctx->Input) {
		ctx->Input = _Input;
		MEMCPY(ctx->Input, ctx->IV, ctx->blockSize * sizeof(uint8_t));
	}

	plaintext = ctx->encrypt_block_method(ctx->Input, ctx->keys);
	
	MEMCPY(ctx->Input, plaintext, ctx->blockSize * sizeof(uint8_t));

	for (unsigned int i = 0; i < ctx->blockSize; ++i)
		plaintext[i] ^= ciphertext[i];

	return plaintext;
}


bytes_t EncryptCFB_block(Block_ctx* ctx, bytes_t plaintext) {
	
	bytes_t ciphertext = 0;

	if (!ctx->Input) {
		ctx->Input = _Input;
		MEMCPY(ctx->Input, ctx->IV, ctx->blockSize * sizeof(uint8_t));
	}

	ciphertext = ctx->encrypt_block_method(ctx->Input, ctx->keys);
	
	for (unsigned int i = 0; i < ctx->blockSize; ++i)
		ciphertext[i] ^= plaintext[i];

	MEMCPY(ctx->Input, ciphertext, ctx->blockSize * sizeof(uint8_t));

	return ciphertext;
}

bytes_t DecryptCFB_block(Block_ctx* ctx, bytes_t ciphertext) {
	
	bytes_t plaintext = 0;

	if (!ctx->Input) {
		ctx->Input = _Input;
		MEMCPY(ctx->Input, ctx->IV, ctx->blockSize * sizeof(uint8_t));
	}
	
	plaintext = ctx->encrypt_block_method(ctx->Input, ctx->keys);

	for (unsigned int i = 0; i < ctx->blockSize; ++i)
		plaintext[i] ^= ciphertext[i];

	MEMCPY(ctx->Input, ciphertext, ctx->blockSize * sizeof(uint8_t));

	return plaintext;
}

bytes_t EncryptCTR_block(Block_ctx* ctx, bytes_t plaintext) {
	
	bytes_t ciphertext = 0;

	if (!ctx->Input)
		ctx->Input = _Input;

	
	unsigned int* temp = (unsigned int*)ctx->Nonce;

	*temp += ctx->Counter;

	bytes_t SumRes = (bytes_t)temp;

	for (unsigned int i = 0; i < ctx->blockSize; ++i)
		ctx->Input[i] = SumRes[i];

	++ctx->Counter;

	ciphertext = ctx->encrypt_block_method(ctx->Input, ctx->keys);

	for (unsigned int i = 0; i < ctx->blockSize; ++i)
		ciphertext[i] ^= plaintext[i];

	return ciphertext;
} 

bytes_t DecryptCTR_block(Block_ctx* ctx, bytes_t ciphertext) {
	
	bytes_t plaintext = 0;

	if (!ctx->Input)
		ctx->Input = _Input;

	unsigned int* temp = (unsigned int*)ctx->Nonce;

	*temp += ctx->Counter;

	bytes_t SumRes = (bytes_t)temp;

	for (unsigned int i = 0; i < ctx->blockSize; ++i)
		ctx->Input[i] = SumRes[i];

	++ctx->Counter;

	plaintext = ctx->encrypt_block_method(ctx->Input, ctx->keys);

	for (unsigned int i = 0; i < ctx->blockSize; ++i)
		plaintext[i] ^= ciphertext[i];

	return plaintext;
} 
