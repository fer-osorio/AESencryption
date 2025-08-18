#include<stdint.h>
#include<stddef.h>

/*
 * Encrypts the data pointed by 'input' using ECB operation mode.
 * The resulting data is written on the location pointed by 'output'.
 * */
void encryptECB(const uint8_t*const input, size_t size, uint8_t*const output);
