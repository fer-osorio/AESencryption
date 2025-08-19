#include"cipher.h"

/*
 * Takes 16 bytes, converts to block, encrypts and writes on output.
 * If input == output, original data will be rewritten with encrypted data.
 * */
void encryptBlockBytes(const uint8_t*const input, const Block *keyExpansion, Nk nk, uint8_t* output);

/*
 * Takes 16 bytes, converts to block, decrypts and writes on output.
 * If input == output, original data will be rewritten with decrypted data.
 * */
void decryptBlockBytes(const uint8_t*const input, const Block *keyExpansion, Nk nk, uint8_t* output);

/*
 * Encrypts the data pointed by 'input' using ECB operation mode.
 * The resulting data is written on the location pointed by 'output'.
 * If input == output (they point to the same location), the input data will be overwritten with the encrypted data.
 * */
void encryptECB(const uint8_t*const input, size_t size, const Block *keyExpansion, Nk nk, uint8_t*const output);

/*
 * Decrypts the data pointed by 'input' using ECB operation mode.
 * The resulting data is written on the location pointed by 'output'.
 * If input == output (they point to the same location), the input data will be overwritten with the decrypted data.
 * */
void decryptECB(const uint8_t*const input, size_t size, const Block *keyExpansion, Nk nk, uint8_t*const output);
