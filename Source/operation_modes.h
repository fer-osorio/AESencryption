#include"cipher.h"

/*
 * Encrypts the data pointed by 'input' using ECB operation mode.
 * The resulting data is written on the location pointed by 'output'.
 * If input == output (they point to the same location), the input data will be overwritten with the encrypted data.
 * */
void encryptECB(const uint8_t*const input, size_t size, KeyExpansion_ptr ke_p, uint8_t*const output);

/*
 * Decrypts the data pointed by 'input' using ECB operation mode.
 * The resulting data is written on the location pointed by 'output'.
 * If input == output (they point to the same location), the input data will be overwritten with the decrypted data.
 * */
void decryptECB(const uint8_t*const input, size_t size, KeyExpansion_ptr ke_p, uint8_t*const output);

/*
 * Encrypts the data pointed by 'input' using CBC operation mode.
 * The resulting data is written on the location pointed by 'output'.
 * If input == output (they point to the same location), the input data will be overwritten with the encrypted data.
 * IV argument carries a reference to the initial vector intended to be used for the encryption.
 * */
void encryptCBC(const uint8_t*const input, size_t size, KeyExpansion_ptr ke_p, const uint8_t* IV, uint8_t*const output);

/*
 * Decrypts the data pointed by 'input' using CBC operation mode.
 * The resulting data is written on the location pointed by 'output'.
 * If input == output (they point to the same location), the input data will be overwritten with the decrypted data.
 * IV argument carry a reference to the initial vector used for encryption.
 * */
void decryptCBC(const uint8_t*const input, size_t size, KeyExpansion_ptr ke_p, const Block* IV, uint8_t*const output);
