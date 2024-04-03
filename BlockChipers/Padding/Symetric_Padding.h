#ifndef SYMETRIC_PADDING_H_
#define SYMETRIC_PADDING_H_
#include "../../util/util_types.h"

void byte_padding(bytes_t, uint8_t, uint8_t);
void x9_23_padding(bytes_t, uint8_t, uint8_t);
void pkcs_5_7_padding(bytes_t, uint8_t, uint8_t);

uint8_t remove_byte_padding(bytes_t, uint8_t);
uint8_t remove_x9_23_padding(bytes_t, uint8_t);
uint8_t remove_pkcs_5_7_padding(bytes_t, uint8_t);


#endif
