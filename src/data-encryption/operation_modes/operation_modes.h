#ifndef OPERATION_MODES_H
#define OPERATION_MODES_H

#include<stdint.h>
#include<stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Encrypts the data pointed by 'input' using ECB operation mode.
 * The resulting data is written on the location pointed by 'output'.
 * If input == output (they point to the same location), the input data will be overwritten with the encrypted data.
 * */
void encryptECB(const uint8_t*const input, size_t size, const uint8_t* keyexpansion, size_t Nk, uint8_t*const output);

/*
 * Decrypts the data pointed by 'input' using ECB operation mode.
 * The resulting data is written on the location pointed by 'output'.
 * If input == output (they point to the same location), the input data will be overwritten with the decrypted data.
 * */
void decryptECB(const uint8_t*const input, size_t size, const uint8_t* keyexpansion, size_t Nk, uint8_t*const output);

/*
 * Writes random values on the BLOCK_SIZE bytes pointed by IVlocation. Intended for Initial Vector initialization.
 * */
void setInitialVector(uint8_t*const IVlocation);

/*
 * Encrypts the data pointed by 'input' using CBC operation mode.
 * The resulting data is written on the location pointed by 'output'.
 * If input == output (they point to the same location), the input data will be overwritten with the encrypted data.
 * IV argument carries a reference to the initial vector intended to be used for the encryption.
 * */
void encryptCBC(const uint8_t*const input, size_t size, const uint8_t* keyexpansion, size_t Nk, const uint8_t* IV, uint8_t*const output);

/*
 * Decrypts the data pointed by 'input' using CBC operation mode.
 * The resulting data is written on the location pointed by 'output'.
 * If input == output (they point to the same location), the input data will be overwritten with the decrypted data.
 * IV argument carry a reference to the initial vector used for encryption.
 * */
void decryptCBC(const uint8_t*const input, size_t size, const uint8_t* keyexpansion, size_t Nk, const uint8_t* IV, uint8_t*const output);

#ifdef __cplusplus
}
#endif

#endif
