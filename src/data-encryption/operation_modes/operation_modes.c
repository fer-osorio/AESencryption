#include"operation_modes.h"
#include"../AES/AES.h"

struct InputOutputHandler{
  const uint8_t*const input;
  uint8_t*const output;
  const size_t size;
  const size_t sizeInBlocks;
  const size_t tailSize;
  const uint8_t* inputCurrentPossition;
  uint8_t* outputCurrentPossition;
};

static struct InputOutputHandler InputOutputHandlerInitialize(uint8_t*const input, uint8_t*const output, const size_t size){
  struct InputOutputHandler ioh = {input, output, size, size / BLOCK_SIZE, size % BLOCK_SIZE, input, output};
  return ioh;
}

static void InputOutputHandlerMoveForwardOneBlock(struct InputOutputHandler* ioh){
  ioh->inputCurrentPossition += BLOCK_SIZE;
  ioh->inputCurrentPossition += BLOCK_SIZE;
}

/*
 * Takes 16 bytes, converts to block, encrypts and writes on output.
 * If input == output, original data will be rewritten with encrypted data.
 * */
static void encryptBlockBytes(const uint8_t*const input, const KeyExpansion* ke_p, uint8_t* output){
  Block* buffer;
  blockFromBytes(input, buffer);
  encryptBlock(buffer, ke_p, buffer, false);
  bytesFromBlock(buffer, output);
}

static void InputOutputHandlerEncryptBlockBytes(const struct InputOutputHandler* ioh, const KeyExpansion* ke_p){
  encryptBlockBytes(ioh->inputCurrentPossition, ke_p, ioh->outputCurrentPossition);
}

/*
 * Takes 16 bytes, converts to block, decrypts and writes on output.
 * If input == output, original data will be rewritten with decrypted data.
 * */
static void decryptBlockBytes(const uint8_t*const input, const KeyExpansion* ke_p, uint8_t* output){
  Block* buffer;
  blockFromBytes(input, buffer);
  decryptBlock(buffer, ke_p, buffer);
  bytesFromBlock(buffer, output);
}

/*
 * Moves forward an amount of BLOCK_SIZE bytes the pointers pointed by the non-null arguments
 * Notice: Last argument is a pointer to non-constant object
 * */
static void movePointerForwardOneBlock(const uint8_t** ptr1, uint8_t** ptr2_nonConstant){
  if(ptr1 != NULL) *ptr1 += BLOCK_SIZE;
  if(ptr2_nonConstant != NULL) *ptr2_nonConstant += BLOCK_SIZE;
}

static void encryptECB__(const KeyExpansion* ke_p, struct InputOutputHandler* ioh){
  if(ioh->size == 0 || ioh->input == NULL) return;
  if(ioh->sizeInBlocks == 0) return;  // -Not handling the case size < 16

  InputOutputHandlerEncryptBlockBytes(ioh, ke_p);
  for(size_t i = 1; i < ioh->sizeInBlocks; i++) {
    InputOutputHandlerMoveForwardOneBlock(ioh);
    InputOutputHandlerEncryptBlockBytes(ioh, ke_p);
  }
  // -Handling the case where input size is not multiple of 16. This is not specified in the NIST standard.
  if(ioh->tailSize != 0) {
    encryptBlockBytes(ioh->inputCurrentPossition + ioh->tailSize, ke_p, ioh->outputCurrentPossition + ioh->tailSize);
  }
}

static void decryptECB__(const KeyExpansion* ke_p, struct InputOutputHandler* ioh){
  if(size == 0 || input == NULL) return;
  const uint8_t* inputCurrentPossition = input;
  uint8_t* outputCurrentPossition = output;
  const size_t numBlocks = size / BLOCK_SIZE;
  const size_t numBlocks_1 = numBlocks - 1;
  const size_t rem = size % BLOCK_SIZE;

  if(numBlocks == 0) return;  // -Not handling the case size < 16
  decryptBlockBytes(inputCurrentPossition, ke_p, outputCurrentPossition);
  for(size_t i = 1; i < numBlocks; i++) {
    movePointerForwardOneBlock(&inputCurrentPossition, &outputCurrentPossition);
    decryptBlockBytes(inputCurrentPossition, ke_p, outputCurrentPossition);
  }
  if(rem != 0) {                                                                // -This part of the code is for encrypt input that its size is not multiple of 16.
    decryptBlockBytes(inputCurrentPossition + rem, ke_p, outputCurrentPossition + rem); //  This is not specified in the NIST standard.
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

static void encryptCBCsingleBlockBytes(const uint8_t*const input, const KeyExpansion* ke_p, const uint8_t* XORsource, uint8_t* output){
  Block* buffer;
  blockFromBytes(input, buffer);
  XORequalBlockWithBytes(buffer, XORsource);
  encryptBlock(buffer, ke_p, buffer, false);
  bytesFromBlock(buffer, output);
}

void encryptCBC(const uint8_t*const input, size_t size, const KeyExpansion* ke_p, const uint8_t* IV, uint8_t*const output){
  if(size == 0 || input == NULL) return;
  const uint8_t* inputCurrentPossition = input;
  const uint8_t* inputPreviousBlock;
  uint8_t* outputCurrentPossition = output;
  const size_t numBlocks = size / BLOCK_SIZE;
  const size_t numBlocks_1 = numBlocks - 1;
  const size_t rem = size % BLOCK_SIZE;

  encryptCBCsingleBlockBytes(inputCurrentPossition, ke_p, IV, outputCurrentPossition);       // -Encryption of the first block.

  for(size_t i = 1; i < numBlocks; i++) {                                       // -Encryption of the rest of the blocks.
    inputPreviousBlock = inputCurrentPossition;
    movePointerForwardOneBlock(&inputCurrentPossition, NULL, &outputCurrentPossition);
    encryptCBCsingleBlockBytes(inputCurrentPossition, ke_p, inputPreviousBlock, outputCurrentPossition);
  }
  if(rem != 0) {                                                                // -This part of the code is for encrypt input that its size is not multiple of 16.
      size_t k = numBlocks*BLOCK_SIZE, i;                                       //  This is not specified in the NIST standard.
      for(i = 0; i < rem; i++,k++) output[k] = inputCurrentPossition[k] ^ inputPreviousBlock[k];
      encryptBlockBytes(inputPreviousBlock + rem, ke_p, outputCurrentPossition + rem);
  }
}
