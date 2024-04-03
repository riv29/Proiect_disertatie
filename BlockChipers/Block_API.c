#include "Block_API.h"
#include "Modes/Modes.h"
#include "Padding/Symetric_Padding.h"
#include "AES/AES.h"
#include "DES/DES.h"
#include "RC6/RC6.h"

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

//TODO: Delete this
#include <stdio.h>

#ifndef FILE_BUF_SIZE
#define FILE_BUF_SIZE 4096
#endif

static Block_ctx* ctx = 0;
static uint8_t keys[768]; // This should be 176 at best but since for now DES has a byte approach of representing bits the cipher is not optimal so we're stuck with a dimension of 16 * 48 instead of 16 * 6

/* Private functions */
void ResetContext() {	
	ctx->type = NO_CIPHER;
	ctx->Counter = 0;

	// Set the default block mode to ECB
	ctx->encrypt = EncryptECB;
	ctx->decrypt = DecryptECB;

	ctx->encrypt_block = EncryptECB_block;
	ctx->decrypt_block = DecryptECB_block;

	// Set the default padding to byte padding
	ctx->add_padding = byte_padding;
	ctx->remove_padding = remove_byte_padding;

	ctx->blockSize = 0;

	*(ctx->keys) = keys;
	ctx->keySchedule = 0;

	ctx->encrypt_block_method = 0;
	ctx->decrypt_block_method = 0;
	
	ctx->encrypt_method = 0;
	ctx->decrypt_method = 0;
}

int PrepareKeys(bytes_t key) {
	if (ctx == 0 || ctx->keySchedule == 0)
		return 1;
	uint8_t processed_key[32] = {0};
	uint8_t key_size = 0;
	for (; key[key_size] != '\0'; ++key_size);
	for (unsigned int i = 0; i < ctx->blockSize; processed_key[i] = key[i % key_size], ++i);

	ctx->keySchedule(ctx->keys, processed_key);
	return 0;
}

void SetIV(uint8_t IV[32]) {
	Block_ctx* context = GetContext();
	uint8_t i = 0;
	for (; i < context->blockSize && IV[i] != '\0'; ++i)
		context->IV[i] = IV[i];
	for (; i < context->blockSize; ++i)
		context->IV[i] = '\0';
}

void SetNonce(uint8_t Nonce[32]) {
	Block_ctx* context = GetContext();
	uint8_t i = 0;
	for (; i < context->blockSize && Nonce[i] != '\0'; ++i)
		context->Nonce[i] = Nonce[i];
	for (; i < context->blockSize; ++i)
		context->Nonce[i] = '\0';
}

/* Public functions */
Block_ctx* GetContext() {

	if (ctx == 0) {
		ctx = (Block_ctx*)malloc(sizeof(Block_ctx));

		ResetContext();
	}

	return ctx;	
}

void ClearContext() {
	if (ctx != 0)
		free(ctx);

	ctx = 0;
}

int InitContext(Block_cipher cipher_type) {

	GetContext();
	
	ctx->type = cipher_type;

	switch (cipher_type) {
		case AES_128:
		case AES_192:
		case AES_256:
			ctx->blockSize			= 16;
			ctx->keySchedule 		= AESKeySchedule;
			
			ctx->encrypt_block_method	= AES_encrypt_block;
			ctx->encrypt_method		= AES_encrypt;

			ctx->decrypt_block_method	= AES_decrypt_block;
			ctx->decrypt_method		= AES_decrypt;
			
			// Set the global variable used in AES/AES.c
			AES_type			= cipher_type;

			break;
		case DES:
		case TRIPLE_DES:
			ctx->blockSize			= 8;
			ctx->keySchedule		= DESKeySchedule;

			ctx->encrypt_block_method	= DES_encrypt_block;
			ctx->encrypt_method		= DES_encrypt;

			ctx->decrypt_block_method	= DES_decrypt_block;
			ctx->decrypt_method		= DES_decrypt;
			break;
		case RC6_128:
		case RC6_192:
		case RC6_256:
			ctx->blockSize			= 16;
			ctx->keySchedule		= RC6KeySchedule;

			ctx->encrypt_block_method	= RC6_encrypt_block;
			ctx->encrypt_method		= RC6_encrypt;

			ctx->decrypt_block_method	= RC6_decrypt_block;
			ctx->decrypt_method		= RC6_decrypt;

			Config.r = 20;
			Config.w = 32;
			Config.b = 16 + (8 * (cipher_type - RC6_128));
			break;
		//case ARIA:
		//	ctx.blockSize = 16;
		//	break;
		//case BLOWFISH:
		//	ctx.blockSize = 8;
		//	break;
		default:
			return 1;
	}

	return 0;
}

void SetMode(Block_opmode mode, uint8_t Vector[32]) {
	if (mode != CTR)
		SetIV(Vector);
	else {
		ctx->encrypt = EncryptCTR;
		ctx->decrypt = DecryptCTR;
		ctx->encrypt_block = EncryptCTR_block;
		ctx->decrypt_block = DecryptCTR_block;
		SetNonce(Vector);
		return;
	}
	switch(mode) {
		case CBC:
			ctx->encrypt = EncryptCBC;
			ctx->decrypt = DecryptCBC;
			ctx->encrypt_block = EncryptCBC_block;
			ctx->decrypt_block = DecryptCBC_block;
			break;
		case OFB:
			ctx->encrypt = EncryptOFB;
			ctx->decrypt = DecryptOFB;
			ctx->encrypt_block = EncryptOFB_block;
			ctx->decrypt_block = DecryptOFB_block;
			break;
		case CFB:
			ctx->encrypt = EncryptCFB;
			ctx->decrypt = DecryptCFB;
			ctx->encrypt_block = EncryptCFB_block;
			ctx->decrypt_block = DecryptCFB_block;
			break;
		default: 
			ctx->encrypt = EncryptECB;
			ctx->decrypt = DecryptECB;
			ctx->encrypt_block = EncryptECB_block;
			ctx->decrypt_block = DecryptECB_block;
			break;
	}
}

void SetPadding(Padding_type padding) {
	switch (padding) {
		case X9_23:
			ctx->add_padding = x9_23_padding;
			ctx->remove_padding = remove_x9_23_padding;
			break;
		case PKCS_5_7:
			ctx->add_padding = pkcs_5_7_padding;
			ctx->remove_padding = remove_pkcs_5_7_padding;
			break;
		default:
			ctx->add_padding = byte_padding;
			ctx->remove_padding = remove_byte_padding;
			break;
	}
}

size_t decrypt_blob(bytes_t* plain_text, bytes_t cipher_text, bytes_t key, size_t len) {
	PrepareKeys(key);
	size_t end_pos = (size_t)cipher_text + len;
	if (*plain_text != 0)
		free(*plain_text);
	*plain_text = (bytes_t)malloc(len);
	uint8_t *text_ptr = cipher_text, *plain_text_ptr = *plain_text;
	for (; (size_t)text_ptr + ctx->blockSize < end_pos; text_ptr += ctx->blockSize, plain_text_ptr += ctx->blockSize)
		ctx->decrypt(ctx, plain_text_ptr, text_ptr);
	ctx->decrypt(ctx, plain_text_ptr, text_ptr);
	// Remove_padding
	uint8_t padding_offset = ctx->remove_padding(plain_text_ptr, ctx->blockSize);
	len -= ctx->blockSize - padding_offset;
	return len;
}

off_t decrypt_from_file(bytes_t path, bytes_t* plain_text, bytes_t key) {
	
	Block_ctx* context = GetContext();
	
	context->Counter = 0;
	context->Input = 0;

	int fp = open(path, O_RDONLY, 0666);
	if (fp == -1)
		return 1;
	
	off_t file_size = lseek(fp, 0, SEEK_END);
	lseek(fp, 0, SEEK_SET);
	
	PrepareKeys(key);
	uint8_t buf[FILE_BUF_SIZE];
	unsigned short buf_len = 0;
	
	if (*plain_text != 0)
		free(*plain_text);
	*plain_text = (bytes_t)malloc(file_size);
	bytes_t plain_text_ptr = *plain_text;
	
	off_t offset = 0;
	for (; offset + FILE_BUF_SIZE < file_size; offset += FILE_BUF_SIZE) {
		buf_len = read(fp, buf, FILE_BUF_SIZE);
		for (unsigned short i = 0; i < buf_len; i += context->blockSize, plain_text_ptr += context->blockSize)
			context->decrypt(context, plain_text_ptr, buf + i);
	}
	buf_len = read(fp, buf, file_size - offset);
	for (unsigned short i = 0; i < buf_len; i += context->blockSize, plain_text_ptr += context->blockSize)
		context->decrypt(context, plain_text_ptr, buf + i);

	close(fp);
	// Remove_padding
	uint8_t padding_offset = context->remove_padding(plain_text_ptr, context->blockSize);
	file_size -= context->blockSize - padding_offset;
	return file_size;
}

size_t encrypt_blob(bytes_t* cipher_text, bytes_t plain_text, bytes_t key, size_t len) {
	PrepareKeys(key);
	size_t end_pos = (size_t)plain_text + len;
	if (*cipher_text != 0)
		free(*cipher_text);
	*cipher_text = (bytes_t)malloc(len + (ctx->blockSize - (len % ctx->blockSize)));
	uint8_t *text_ptr = plain_text, *cipher_text_ptr = *cipher_text;
	for (; (size_t)text_ptr + ctx->blockSize <= end_pos; text_ptr += ctx->blockSize, cipher_text_ptr += ctx->blockSize)
		ctx->encrypt(ctx, cipher_text_ptr, text_ptr);
	// Apply_padding
	uint8_t offset = 0;
	for (; (size_t)text_ptr < end_pos; cipher_text_ptr[offset] = *text_ptr, ++offset, ++text_ptr);
	ctx->add_padding(cipher_text_ptr, offset, ctx->blockSize);
	ctx->encrypt(ctx, cipher_text_ptr, cipher_text_ptr);
	return (size_t)cipher_text;
}

int encrypt_to_file(bytes_t path, bytes_t plain_text, bytes_t key, size_t len) {

	Block_ctx* context = GetContext();

	context->Counter = 0;
	context->Input = 0;

	int fp = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0666);
	if (fp == -1)
		return 1;
	PrepareKeys(key);
	uint8_t buf[FILE_BUF_SIZE];
	unsigned short buf_len = 0;
	size_t offset = 0;
	for (; offset + context->blockSize <= len;) {
		context->encrypt(context, buf + buf_len, plain_text + offset);
		offset += context->blockSize;
		buf_len = offset % FILE_BUF_SIZE;
		if (!(buf_len % FILE_BUF_SIZE)) {
			if (-1 == write(fp, buf, FILE_BUF_SIZE))
				return 1;
		}
	}
	uint8_t index = 0;
	context->add_padding(plain_text + offset, len - offset, context->blockSize);
	context->encrypt(context, buf + buf_len, plain_text + offset);
	buf_len += 16;
	int res = (-1 == write(fp, buf, buf_len));
	close(fp);
	return res;
}
