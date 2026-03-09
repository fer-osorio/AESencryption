#ifndef CIPHER_H
#define CIPHER_H

#ifdef __cplusplus
extern "C" {
#endif

#include "block.h"
#include "key_expansion.h"
#include "exception_code.h"
#include <stdbool.h>

/*
 * Encrypts input block using the key referenced by ke_p, the resultant encrypted block is written in output.
 * If input == output (they point to the same memory location), the input block is overwritten with the encrypted data.
 * */
enum ExceptionCode encryptBlock(const Block_t* input, const KeyExpansion_t* ke_p, Block_t* output, bool debug);

/*
 * Decrypts input block using the key referenced by ke_p, the resultant decrypted block is written in output.
 * If input == output (they point to the same memory location), the input block is overwritten with the decrypted data.
 * */
enum ExceptionCode decryptBlock(const Block_t* input, const KeyExpansion_t* ke_p, Block_t* output, bool debug);

#ifdef __cplusplus
}
#endif

#endif
