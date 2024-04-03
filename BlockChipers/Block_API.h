#ifndef BLOCK_API_H_
#define BLOCK_API_H_
#include "Block_util.h"

int InitContext(Block_cipher);
void SetMode(Block_opmode, uint8_t[32]);
void SetPadding(Padding_type);

size_t decrypt_blob(bytes_t*, bytes_t, bytes_t, size_t);
off_t decrypt_from_file(bytes_t, bytes_t*, bytes_t);
size_t encrypt_blob(bytes_t*, bytes_t, bytes_t, size_t);
int encrypt_to_file(bytes_t, bytes_t, bytes_t, size_t);

#endif
