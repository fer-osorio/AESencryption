#include"operation_modes.h"

void encryptBlockBytes(const uint8_t*const input, const Block *keyExpansion, Nk nk, uint8_t* output){
  Block buffer;
  blockFromBytes(input, &buffer);
  encryptBlock(&buffer, keyExpansion, nk, &buffer, false);
  bytesFromBlock(&buffer, output);
}

void decryptBlockBytes(const uint8_t*const input, const Block *keyExpansion, Nk nk, uint8_t* output){
  Block buffer;
  blockFromBytes(input, &buffer);
  decryptBlock(&buffer, keyExpansion, nk, &buffer);
  bytesFromBlock(&buffer, output);
}

void encryptECB(const uint8_t*const input, size_t size, const Block *keyExpansion, Nk nk, uint8_t*const output){
  if(size == 0 || input == NULL) return;
  const uint8_t* inputCurrentPossition = input;
  uint8_t* outputCurrentPossition = output;
  size_t numBlocks = size >> 4, numBlocks_1 = numBlocks - 1;                    //  numBlocks = size / 16.
  size_t rem = size & 15, i;                                                    // -Bytes remaining rem = size % 16

  for(i = 0; i < numBlocks_1; i++) {
    encryptBlockBytes(inputCurrentPossition, keyExpansion, nk, outputCurrentPossition);
    inputCurrentPossition += BLOCK_SIZE;
    outputCurrentPossition += BLOCK_SIZE;
  }
  encryptBlockBytes(inputCurrentPossition, keyExpansion, nk, outputCurrentPossition); // -Handling the case where input size is not multiple of 16.
  if(rem != 0) {                                                                //  This is not specified in the NIST standard.
    encryptBlockBytes(inputCurrentPossition + rem, keyExpansion, nk, outputCurrentPossition + rem);
  }
  // -Not handling the case size < 16
}

void decryptECB(const uint8_t*const input, size_t size, const Block *keyExpansion, Nk nk, uint8_t*const output){
  if(size == 0 || input == NULL) return;
  const uint8_t* inputCurrentPossition = input;
  uint8_t* outputCurrentPossition = output;
  size_t numBlocks = size >> 4, numBlocks_1 = numBlocks - 1;                    //  numBlocks = size / 16.
  size_t rem = size & 15, i;                                                    // -Bytes remaining rem = size % 16

  for(i = 0; i < numBlocks_1; i++) {
    decryptBlockBytes(inputCurrentPossition, keyExpansion, nk, outputCurrentPossition);
    inputCurrentPossition += BLOCK_SIZE;
    outputCurrentPossition += BLOCK_SIZE;
  }
  if(rem != 0) {                                                                // -This part of the code is for encrypt input that its size is not multiple of 16.
    decryptBlockBytes(inputCurrentPossition + rem, keyExpansion, nk, outputCurrentPossition + rem); //  This is not specified in the NIST standard.
  }
  decryptBlockBytes(inputCurrentPossition, keyExpansion, nk, outputCurrentPossition);
  // -Not handling the case size < 16
}
