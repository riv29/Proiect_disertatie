#include <stdio.h>
#include <stdlib.h>
#include "Base64.h"

#define ENCODE_BLOCK(dest, src, nr_bytes) {\
					(dest)[0] = ((src)[0] >> 2) & 0x3f;\
					(dest)[1] = ((((src)[0] & 0x3) << 4) | ((nr_bytes > 1) * (((src)[1] >> 4) & 0xf))) & 0x03f;\
					(dest)[2] = (((nr_bytes > 1) ? (((src)[1] & 0xf) << 2) : 64) | ((nr_bytes > 2) * (((src)[2] >> 6) & 0x03))) & 0x3f;\
					(dest)[3] = ((nr_bytes > 2) ? ((src)[2] & 0x3f) : 64) & 0x3f;\
				}

#define APPLY_ALPHABET(character) ((character < 26) ? ('A' + character) : (character < 52) ? ('a' + (character - 26)) : (character < 62) ? ('0' + (character - 52)) : (character == 62) * '+' + (character == 63) * '/' + (character == 64) * '=')

#define DECODE_BLOCK(dest, src) {\
					(dest)[0] = (((src)[0] << 2) & 0xfc) | (((src)[1] >> 4) & 0x03);\
					(dest)[1] = (((src)[1] << 4) & 0xf0) | (((src)[2] >> 2) & 0xff);\
					(dest)[2] = (((src)[2] << 6) & 0xc0) | ((src)[3] & 0x3f);\
				}

#define TRANSLATE_ALPHABET(character) ((character == '+') ? 62 : (character == '/') ? 63 : (character <= '9') ? (character - '0' + 52) : (character == '=') ? 0 : (character <= 'Z') ? (character - 'A') : (character - 'a' + 26))

unsigned char* encode_text(char* input_text, size_t len) {
	size_t i = 0;
	unsigned char* res = (unsigned char*)malloc(((len / 3 + (len % 3 > 0)) * 4) + 1);
	for (; i < len / 3; ++i)
		ENCODE_BLOCK(res + i * 4, input_text + i * 3, 3);
	if (i * 3 < len)
		ENCODE_BLOCK(res + i * 4, input_text + i * 3, len - i * 3);
	for (i = 0; i < (len / 3 + (len % 3 > 0)) * 4; ++i)
		res[i] = APPLY_ALPHABET(res[i]);
	res[(len / 3 + (len % 3 > 0)) * 4] = '\0';
	return res;
}

unsigned char* decode_text(char* input_text, size_t len) {
	unsigned char* res = (unsigned char*)calloc(len / 4 * 3 + 1, 1);
	size_t i = 0;
	for (i = 0; i < len; ++i)
		input_text[i] = TRANSLATE_ALPHABET(input_text[i]);
	for (i = 0; i < len / 4; ++i)
		DECODE_BLOCK(res + i * 3, input_text + i * 4);
	return res;
}
