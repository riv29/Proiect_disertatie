#ifndef MODES_H_
#define MODES_H_
#include "../Block_util.h"

int EncryptECB(Block_ctx*, bytes_t, bytes_t);
int DecryptECB(Block_ctx*, bytes_t, bytes_t);
int EncryptCBC(Block_ctx*, bytes_t, bytes_t);
int DecryptCBC(Block_ctx*, bytes_t, bytes_t);
int EncryptOFB(Block_ctx*, bytes_t, bytes_t);
int DecryptOFB(Block_ctx*, bytes_t, bytes_t);
int EncryptCFB(Block_ctx*, bytes_t, bytes_t);
int DecryptCFB(Block_ctx*, bytes_t, bytes_t);
int EncryptCTR(Block_ctx*, bytes_t, bytes_t);
int DecryptCTR(Block_ctx*, bytes_t, bytes_t);

bytes_t EncryptECB_block(Block_ctx*, bytes_t);
bytes_t DecryptECB_block(Block_ctx*, bytes_t);
bytes_t EncryptCBC_block(Block_ctx*, bytes_t);
bytes_t DecryptCBC_block(Block_ctx*, bytes_t);
bytes_t EncryptOFB_block(Block_ctx*, bytes_t);
bytes_t DecryptOFB_block(Block_ctx*, bytes_t);
bytes_t EncryptCFB_block(Block_ctx*, bytes_t);
bytes_t DecryptCFB_block(Block_ctx*, bytes_t);
bytes_t EncryptCTR_block(Block_ctx*, bytes_t);
bytes_t DecryptCTR_block(Block_ctx*, bytes_t);

#endif
