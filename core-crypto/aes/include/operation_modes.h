/**
 * @file operation_modes.h
 * @brief AES block cipher operation modes (ECB CBC, OFB, and CTR)
 *
 * This file provides AES encryption and decryption functions using
 * Electronic Codebook (ECB), Cipher Block Chaining (CBC), Output Feedback Mode (OFB) and Counter (CTR) operation modes.
 * Each modes operate on 16-byte blocks (128 bits).
 *
 * @note All functions support in-place operation when input == output
 * @note All input sizes for ECB and CBC must be multiples of 16 bytes (AES block size)
 * @note The IV for CBC mode must be exactly 16 bytes
 */

#ifndef OPERATION_MODES_H
#define OPERATION_MODES_H

#ifdef __cplusplus
extern "C" {
#endif

#include "exception_code.h"
#include <stdint.h>
#include <stddef.h>

/**
* @brief Encrypts data using AES-ECB (Electronic Codebook) operation mode
*
* Encrypts the data pointed to by 'input' using AES-ECB operation mode.
* The resulting encrypted data is written to the location pointed to by 'output'.
* ECB encrypts each 16-byte block independently without chaining.
*
* @param[in] input Pointer to the input data to be encrypted
* @param[in] size Size of the input data in bytes (must be a multiple of 16)
* @param[in] keyexpansion Pointer to the expanded AES key schedule
* @param[in] keylenbits AES key length in bits (128, 192, or 256)
* @param[out] output Pointer to the output buffer for encrypted data
*                    (must have at least 'size' bytes available)
*
* @return ExceptionCode indicating success or failure
* @retval NoException Operation completed successfully
* @retval NullInput The input pointer is NULL
* @retval NullOutput The output pointer is NULL
* @retval NullKeyExpansion The keyexpansion pointer is NULL
* @retval ZeroLength The size parameter is zero
* @retval InvalidInputSize The size is not a multiple of 16 bytes
* @retval InvalidKeyLength The keylenbits is not 128, 192, or 256
*
* @note If input == output (same memory location), the input data will be
*       overwritten with the encrypted data (in-place encryption)
* @warning ECB mode is not recommended for encrypting data with patterns
*          as identical plaintext blocks produce identical ciphertext blocks,
*          which can leak information. Consider using another mode instead.
*
* @see decryptECB()
* @see encryptCBC()
*/
enum ExceptionCode encryptECB(const uint8_t*const input, size_t size, const uint8_t* keyexpansion, size_t keylenbits, uint8_t*const output);

/**
* @brief Decrypts data using AES-ECB (Electronic Codebook) operation mode
*
* Decrypts the data pointed to by 'input' using AES-ECB operation mode.
* The resulting decrypted data is written to the location pointed to by 'output'.
* ECB decrypts each 16-byte block independently without chaining.
*
* @param[in] input Pointer to the encrypted input data
* @param[in] size Size of the input data in bytes (must be a multiple of 16)
* @param[in] keyexpansion Pointer to the expanded AES key schedule
* @param[in] keylenbits AES key length in bits (128, 192, or 256)
* @param[out] output Pointer to the output buffer for decrypted data
*                    (must have at least 'size' bytes available)
*
* @return ExceptionCode indicating success or failure
* @retval NoException Operation completed successfully
* @retval NullInput The input pointer is NULL
* @retval NullOutput The output pointer is NULL
* @retval NullKeyExpansion The keyexpansion pointer is NULL
* @retval ZeroLength The size parameter is zero
* @retval InvalidInputSize The size is not a multiple of 16 bytes
* @retval InvalidKeyLength The keylenbits is not 128, 192, or 256
*
* @note If input == output (same memory location), the input data will be
*       overwritten with the decrypted data (in-place decryption)
* @note The same key and key length used for encryption must be used
*
* @see encryptECB()
* @see decryptCBC()
*/
enum ExceptionCode decryptECB(const uint8_t*const input, size_t size, const uint8_t* keyexpansion, size_t keylenbits, uint8_t*const output);

/**
* @brief Encrypts data using AES-CBC (Cipher Block Chaining) operation mode
*
* Encrypts the data pointed to by 'input' using AES-CBC operation mode with
* the provided initialization vector (IV). CBC XORs each plaintext block with
* the previous ciphertext block before encryption, providing better security
* than ECB mode.
*
* @param[in] input Pointer to the input data to be encrypted
* @param[in] size Size of the input data in bytes (must be a multiple of 16)
* @param[in] keyexpansion Pointer to the expanded AES key schedule
* @param[in] keylenbits AES key length in bits (128, 192, or 256)
* @param[in] IV Pointer to the 16-byte initialization vector for CBC mode
* @param[out] output Pointer to the output buffer for encrypted data
*                    (must have at least 'size' bytes available)
*
* @return ExceptionCode indicating success or failure
* @retval NoException Operation completed successfully
* @retval NullInput The input pointer is NULL
* @retval NullOutput The output pointer is NULL
* @retval NullKeyExpansion The keyexpansion pointer is NULL
* @retval NullInitialVector The IV pointer is NULL
* @retval ZeroLength The size parameter is zero
* @retval InvalidInputSize The size is not a multiple of 16 bytes
* @retval InvalidKeyLength The keylenbits is not 128, 192, or 256
*
* @note If input == output (same memory location), the input data will be
*       overwritten with the encrypted data (in-place encryption)
* @note The IV should be unpredictable (ideally cryptographically random)
*       and unique for each encryption operation with the same key
* @note The IV must be exactly 16 bytes (128 bits) to match the AES block size
* @note The IV is not secret and is typically transmitted or stored alongside
*       the ciphertext
*
* @see decryptCBC()
* @see encryptECB()
*/
enum ExceptionCode encryptCBC(const uint8_t*const input, size_t size, const uint8_t* keyexpansion, size_t keylenbits, const uint8_t* IV, uint8_t*const output);

/**
* @brief Decrypts data using AES-CBC (Cipher Block Chaining) operation mode
*
* Decrypts the data pointed to by 'input' using AES-CBC operation mode with
* the initialization vector (IV) that was used during encryption.
* The resulting decrypted data is written to the location pointed to by 'output'.
*
* @param[in] input Pointer to the encrypted input data
* @param[in] size Size of the input data in bytes (must be a multiple of 16)
* @param[in] keyexpansion Pointer to the expanded AES key schedule
* @param[in] keylenbits AES key length in bits (128, 192, or 256)
* @param[in] IV Pointer to the 16-byte initialization vector used during encryption
* @param[out] output Pointer to the output buffer for decrypted data
*                    (must have at least 'size' bytes available)
*
* @return ExceptionCode indicating success or failure
* @retval NoException Operation completed successfully
* @retval NullInput The input pointer is NULL
* @retval NullOutput The output pointer is NULL
* @retval NullKeyExpansion The keyexpansion pointer is NULL
* @retval NullInitialVector The IV pointer is NULL
* @retval ZeroLength The size parameter is zero
* @retval InvalidInputSize The size is not a multiple of 16 bytes
* @retval InvalidKeyLength The keylenbits is not 128, 192, or 256
*
* @note If input == output (same memory location), the input data will be
*       overwritten with the decrypted data (in-place decryption)
* @note The IV must be exactly the same 16-byte value used during encryption
* @note The same key and key length used for encryption must be used
*
* @see encryptCBC()
* @see decryptECB()
*/
enum ExceptionCode decryptCBC(const uint8_t*const input, size_t size, const uint8_t* keyexpansion, size_t keylenbits, const uint8_t* IV, uint8_t*const output);

/**
* @brief Encrypts data using AES-OFB (Output Feedback) operation mode
*
* Encrypts the data pointed to by 'input' using AES-OFB operation mode with
* the provided initialization vector (IV). OFB generates a keystream by
* repeatedly encrypting the IV, then XORs it with the plaintext. Encryption
* and decryption are identical operations (same keystream applied via XOR).
*
* @param[in] input Pointer to the input data to be encrypted
* @param[in] size Size of the input data in bytes
* @param[in] keyexpansion Pointer to the expanded AES key schedule
* @param[in] keylenbits AES key length in bits (128, 192, or 256)
* @param[in] IV Pointer to the 16-byte initialization vector for OFB mode
* @param[out] output Pointer to the output buffer for encrypted data
*                    (must have at least 'size' bytes available)
*
* @return ExceptionCode indicating success or failure
* @retval NoException Operation completed successfully
* @retval NullInput The input pointer is NULL
* @retval NullOutput The output pointer is NULL
* @retval NullKeyExpansion The keyexpansion pointer is NULL
* @retval NullInitialVector The IV pointer is NULL
* @retval ZeroLength The size parameter is zero
* @retval InvalidKeyLength The keylenbits is not 128, 192, or 256
*
* @note If input == output (same memory location), the input data will be
*       overwritten with the encrypted data (in-place encryption)
* @note The IV should be unpredictable (ideally cryptographically random)
*       and unique for each encryption operation with the same key
* @note The IV must be exactly 16 bytes (128 bits) to match the AES block size
* @note OFB supports partial blocks: size does not need to be a multiple of 16
* @note OFB is a stream cipher mode: encryption and decryption use the same
*       function (encryptOFB == decryptOFB in effect)
*
* @see decryptOFB()
* @see encryptCBC()
*/
enum ExceptionCode encryptOFB(const uint8_t*const input, size_t size, const uint8_t* keyexpansion, size_t keylenbits, const uint8_t* IV, uint8_t*const output);

/**
* @brief Decrypts data using AES-OFB (Output Feedback) operation mode
*
* Decrypts the data pointed to by 'input' using AES-OFB operation mode with
* the initialization vector (IV) that was used during encryption. Because OFB
* generates an independent keystream, decryption is identical to encryption:
* both operations XOR the data with the same keystream derived from the IV.
*
* @param[in] input Pointer to the encrypted input data
* @param[in] size Size of the input data in bytes
* @param[in] keyexpansion Pointer to the expanded AES key schedule
* @param[in] keylenbits AES key length in bits (128, 192, or 256)
* @param[in] IV Pointer to the 16-byte initialization vector used during encryption
* @param[out] output Pointer to the output buffer for decrypted data
*                    (must have at least 'size' bytes available)
*
* @return ExceptionCode indicating success or failure
* @retval NoException Operation completed successfully
* @retval NullInput The input pointer is NULL
* @retval NullOutput The output pointer is NULL
* @retval NullKeyExpansion The keyexpansion pointer is NULL
* @retval NullInitialVector The IV pointer is NULL
* @retval ZeroLength The size parameter is zero
* @retval InvalidKeyLength The keylenbits is not 128, 192, or 256
*
* @note If input == output (same memory location), the input data will be
*       overwritten with the decrypted data (in-place decryption)
* @note The IV must be exactly the same 16-byte value used during encryption
* @note The same key and key length used for encryption must be used
* @note OFB supports partial blocks: size does not need to be a multiple of 16
*
* @see encryptOFB()
* @see decryptCBC()
*/
enum ExceptionCode decryptOFB(const uint8_t*const input, size_t size, const uint8_t* keyexpansion, size_t keylenbits, const uint8_t* IV, uint8_t*const output);

/**
* @brief Encrypts data using AES-CTR (Counter) operation mode
*
* Encrypts the data pointed to by 'input' using AES-CTR operation mode with
* the provided initial counter block. CTR generates a keystream by encrypting
* successive counter values and XORing with the plaintext. The counter is
* incremented as a 64-bit little-endian integer after each block.
*
* @param[in] input Pointer to the input data to be encrypted
* @param[in] size Size of the input data in bytes
* @param[in] keyexpansion Pointer to the expanded AES key schedule
* @param[in] keylenbits AES key length in bits (128, 192, or 256)
* @param[in] counter00 Pointer to the 16-byte initial counter block
* @param[out] output Pointer to the output buffer for encrypted data
*                    (must have at least 'size' bytes available)
*
* @return ExceptionCode indicating success or failure
* @retval NoException Operation completed successfully
* @retval NullInput The input pointer is NULL
* @retval NullOutput The output pointer is NULL
* @retval NullKeyExpansion The keyexpansion pointer is NULL
* @retval NullInitialVector The counter00 pointer is NULL
* @retval ZeroLength The size parameter is zero
* @retval InvalidKeyLength The keylenbits is not 128, 192, or 256
*
* @note If input == output (same memory location), the input data will be
*       overwritten with the encrypted data (in-place encryption)
* @note The counter block is incremented as a 64-bit little-endian integer
*       for each successive block
* @note CTR supports partial blocks: size does not need to be a multiple of 16
* @note CTR is a stream cipher mode: encryption and decryption use the same
*       function (encryptCTR == decryptCTR in effect)
*
* @see decryptCTR()
* @see encryptOFB()
*/
enum ExceptionCode encryptCTR(const uint8_t*const input, size_t size, const uint8_t* keyexpansion, size_t keylenbits, const uint8_t* counter00, uint8_t*const output);

/**
* @brief Decrypts data using AES-CTR (Counter) operation mode
*
* Decrypts the data pointed to by 'input' using AES-CTR operation mode with
* the initial counter block that was used during encryption. Because CTR
* generates an independent keystream, decryption is identical to encryption:
* both operations XOR the data with the same keystream derived from the counter.
*
* @param[in] input Pointer to the encrypted input data
* @param[in] size Size of the input data in bytes
* @param[in] keyexpansion Pointer to the expanded AES key schedule
* @param[in] keylenbits AES key length in bits (128, 192, or 256)
* @param[in] counter00 Pointer to the 16-byte initial counter block used during encryption
* @param[out] output Pointer to the output buffer for decrypted data
*                    (must have at least 'size' bytes available)
*
* @return ExceptionCode indicating success or failure
* @retval NoException Operation completed successfully
* @retval NullInput The input pointer is NULL
* @retval NullOutput The output pointer is NULL
* @retval NullKeyExpansion The keyexpansion pointer is NULL
* @retval NullInitialVector The counter00 pointer is NULL
* @retval ZeroLength The size parameter is zero
* @retval InvalidKeyLength The keylenbits is not 128, 192, or 256
*
* @note If input == output (same memory location), the input data will be
*       overwritten with the decrypted data (in-place decryption)
* @note The counter00 must be exactly the same 16-byte value used during encryption
* @note The same key and key length used for encryption must be used
* @note CTR supports partial blocks: size does not need to be a multiple of 16
*
* @see encryptCTR()
* @see decryptOFB()
*/
enum ExceptionCode decryptCTR(const uint8_t*const input, size_t size, const uint8_t* keyexpansion, size_t keylenbits, const uint8_t* counter00, uint8_t*const output);

#ifdef __cplusplus
}
#endif

#endif
