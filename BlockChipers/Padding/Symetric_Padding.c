#include "Symetric_Padding.h"

void byte_padding(bytes_t block, uint8_t offset, uint8_t blocksize) {
	block[offset] = 0x80;
	for (uint8_t i = offset + 1; i < blocksize; ++i)
		block[i] = 0x0;
}

void x9_23_padding(bytes_t block, uint8_t offset, uint8_t blocksize) {
	block[blocksize - 1] = blocksize - offset;
	for (uint8_t i = offset; i < blocksize - 1; ++i)
		block[i] = 0x0;
}

void pkcs_5_7_padding(bytes_t block, uint8_t offset, uint8_t blocksize) {
	for (uint8_t i = offset, N = blocksize - offset; i < blocksize; ++i)
		block[i] = N;
}

uint8_t remove_byte_padding(bytes_t block, uint8_t blocksize) {
	for (uint8_t offset = blocksize - 1; (offset + 1) > 0; --offset)
		if (block[offset] == 0x80) {
			block[offset] = 0x0;
			return offset;
		}
}

uint8_t remove_x9_23_padding(bytes_t block, uint8_t blocksize) {
	return blocksize - block[blocksize - 1];
}

uint8_t remove_pkcs_5_7_padding(bytes_t block, uint8_t blocksize) {
	return blocksize - block[blocksize - 1];
}
