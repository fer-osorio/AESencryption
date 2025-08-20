#include"operation_modes.h"

/*
 * Takes 16 bytes, converts to block, encrypts and writes on output.
 * If input == output, original data will be rewritten with encrypted data.
 * */
static void encryptBlockBytes(const uint8_t*const input, const Block *keyExpansion, Nk nk, uint8_t* output){
  Block buffer;
  blockFromBytes(input, &buffer);
  encryptBlock(&buffer, keyExpansion, nk, &buffer, false);
  bytesFromBlock(&buffer, output);
}

/*
 * Takes 16 bytes, converts to block, decrypts and writes on output.
 * If input == output, original data will be rewritten with decrypted data.
 * */
static void decryptBlockBytes(const uint8_t*const input, const Block *keyExpansion, Nk nk, uint8_t* output){
  Block buffer;
  blockFromBytes(input, &buffer);
  decryptBlock(&buffer, keyExpansion, nk, &buffer);
  bytesFromBlock(&buffer, output);
}

/*
 * Moves forward an amount of BLOCK_SIZE bytes the pointers pointed by the non-null arguments
 * Notice: Last argument is a pointer to non-constant object
 * */
static void movePointerForwardOneBlock(const uint8_t** ptr1, const uint8_t** ptr2, uint8_t** ptr3_nonConstant){
  if(ptr1 != NULL) *ptr1 += BLOCK_SIZE;
  if(ptr2 != NULL) *ptr2 += BLOCK_SIZE;
  if(ptr3_nonConstant != NULL) *ptr3_nonConstant += BLOCK_SIZE;
}

void encryptECB(const uint8_t*const input, size_t size, const Block *keyExpansion, Nk nk, uint8_t*const output){
  if(size == 0 || input == NULL) return;
  const uint8_t* inputCurrentPossition = input;
  uint8_t* outputCurrentPossition = output;
  const size_t numBlocks = size / BLOCK_SIZE;
  const size_t rem = size % BLOCK_SIZE;

  if(numBlocks == 0) return;  // -Not handling the case size < 16
  encryptBlockBytes(inputCurrentPossition, keyExpansion, nk, outputCurrentPossition);
  for(size_t i = 1; i < numBlocks; i++) {
    movePointerForwardOneBlock(&inputCurrentPossition, NULL, &outputCurrentPossition);
    encryptBlockBytes(inputCurrentPossition, keyExpansion, nk, outputCurrentPossition);
  }
  // -Handling the case where input size is not multiple of 16. This is not specified in the NIST standard.
  if(rem != 0) {
    encryptBlockBytes(inputCurrentPossition + rem, keyExpansion, nk, outputCurrentPossition + rem);
  }
}

void decryptECB(const uint8_t*const input, size_t size, const Block *keyExpansion, Nk nk, uint8_t*const output){
  if(size == 0 || input == NULL) return;
  const uint8_t* inputCurrentPossition = input;
  uint8_t* outputCurrentPossition = output;
  const size_t numBlocks = size / BLOCK_SIZE;
  const size_t numBlocks_1 = numBlocks - 1;
  const size_t rem = size % BLOCK_SIZE;

  if(numBlocks == 0) return;  // -Not handling the case size < 16
  decryptBlockBytes(inputCurrentPossition, keyExpansion, nk, outputCurrentPossition);
  for(size_t i = 1; i < numBlocks; i++) {
    movePointerForwardOneBlock(&inputCurrentPossition, NULL, &outputCurrentPossition);
    decryptBlockBytes(inputCurrentPossition, keyExpansion, nk, outputCurrentPossition);
  }
  if(rem != 0) {                                                                // -This part of the code is for encrypt input that its size is not multiple of 16.
    decryptBlockBytes(inputCurrentPossition + rem, keyExpansion, nk, outputCurrentPossition + rem); //  This is not specified in the NIST standard.
  }
}

/*
 * This function has the same efect than apply the sequence: b = BlockFromBytes(byteBlock), then XORblocks(input, b, input)
 * */
static void XORequalBlockWithBytes(Block* input, const uint8_t byteBlock[]){
  input->uint08_[0] ^= byteBlock[0];
  input->uint08_[1] ^= byteBlock[4];
  input->uint08_[2] ^= byteBlock[8];
  input->uint08_[3] ^= byteBlock[12];
  input->uint08_[4] ^= byteBlock[1];
  input->uint08_[5] ^= byteBlock[5];
  input->uint08_[6] ^= byteBlock[9];
  input->uint08_[7] ^= byteBlock[13];
  input->uint08_[8] ^= byteBlock[2];
  input->uint08_[9] ^= byteBlock[6];
  input->uint08_[10] ^= byteBlock[10];
  input->uint08_[11] ^= byteBlock[14];
  input->uint08_[12] ^= byteBlock[3];
  input->uint08_[13] ^= byteBlock[7];
  input->uint08_[14] ^= byteBlock[11];
  input->uint08_[15] ^= byteBlock[15];
}

static void encryptCBCsingleBlockBytes(const uint8_t*const input, const Block *keyExpansion, Nk nk, const uint8_t* XORsource, uint8_t* output){
  Block buffer;
  blockFromBytes(input, &buffer);
  XORequalBlockWithBytes(&buffer, XORsource);
  encryptBlock(&buffer, keyExpansion, nk, &buffer, false);
  bytesFromBlock(&buffer, output);
}

void encryptCBC(const uint8_t*const input, size_t size, const Block *keyExpansion, Nk nk, const uint8_t* IV, uint8_t*const output){
  if(size == 0 || input == NULL) return;
  const uint8_t* inputCurrentPossition = input;
  const uint8_t* inputPreviousBlock;
  uint8_t* outputCurrentPossition = output;
  const size_t numBlocks = size / BLOCK_SIZE;
  const size_t numBlocks_1 = numBlocks - 1;
  const size_t rem = size % BLOCK_SIZE;

  encryptCBCsingleBlockBytes(inputCurrentPossition, keyExpansion, nk, IV, outputCurrentPossition);       // -Encryption of the first block.

  for(size_t i = 1; i < numBlocks; i++) {                                       // -Encryption of the rest of the blocks.
    inputPreviousBlock = inputCurrentPossition;
    movePointerForwardOneBlock(&inputCurrentPossition, NULL, &outputCurrentPossition);
    encryptCBCsingleBlockBytes(inputCurrentPossition, keyExpansion, nk, inputPreviousBlock, outputCurrentPossition);
  }
  if(rem != 0) {                                                                // -This part of the code is for encrypt input that its size is not multiple of 16.
      size_t k = numBlocks*BLOCK_SIZE, i;                                       //  This is not specified in the NIST standard.
      for(i = 0; i < rem; i++,k++) output[k] = inputCurrentPossition[k] ^ inputPreviousBlock[k];
      encryptBlockBytes(inputPreviousBlock + rem, keyExpansion, nk, outputCurrentPossition + rem);
  }
}
