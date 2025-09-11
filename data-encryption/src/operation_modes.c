#include"../include/constants.h"
#include"../include/AES.h"
#include"../include/operation_modes.h"
#include<string.h>
#include<time.h>

/*
 * Handling pointers that represent the directions of input and output
 * */
struct InputOutputHandler{
  const uint8_t*const input;
  uint8_t*const output;
  const size_t size;
  const size_t sizeInBlocks;
  const size_t tailSize;
  const uint8_t* inputCurrentPossition;
  uint8_t* outputCurrentPossition;
};

static struct InputOutputHandler InputOutputHandlerInitialize(const uint8_t*const input, uint8_t*const output, const size_t size){
  struct InputOutputHandler ioh = {input, output, size, size / BLOCK_SIZE, size % BLOCK_SIZE, input, output};
  return ioh;
}

static void InputOutputHandlerMoveForwardOneBlock(struct InputOutputHandler* ioh){
  ioh->inputCurrentPossition += BLOCK_SIZE;
  ioh->inputCurrentPossition += BLOCK_SIZE;
}

/*
 * Signals if data pointed by ioh->input has a size smaller than BLOCK_SIZE.
 * */
static bool InputOutputHandlerIsSmallerThanBlock(const struct InputOutputHandler* ioh){
  return ioh->input == NULL || ioh->size < BLOCK_SIZE || ioh->sizeInBlocks == 0;
}

/*
 * Takes BLOCK_SIZE bytes, converts to block, encrypts and writes on output.
 * If input == output, original data will be rewritten with encrypted data.
 * */
static void encryptBlockBytes(const uint8_t*const input, const KeyExpansion_t* ke_p, uint8_t* output){
  Block_t* buffer = BlockMemoryAllocationFromBytes(input);
  encryptBlock(buffer, ke_p, buffer, false);
  bytesFromBlock(buffer, output);
  BlockDelete(&buffer);
}

/*
 * Implements encryptBlockBytes on InputOutputHandler object
 * */
static void InputOutputHandlerEncryptBlockBytes(const struct InputOutputHandler* ioh, const KeyExpansion_t* ke_p){
  encryptBlockBytes(ioh->inputCurrentPossition, ke_p, ioh->outputCurrentPossition);
}

/*
 * Takes 16 bytes, converts to block, decrypts and writes on output.
 * If input == output, original data will be rewritten with decrypted data.
 * */
static void decryptBlockBytes(const uint8_t*const input, const KeyExpansion_t* ke_p, uint8_t* output){
  Block_t* buffer = BlockMemoryAllocationFromBytes(input);
  decryptBlock(buffer, ke_p, buffer, false);
  bytesFromBlock(buffer, output);
  BlockDelete(&buffer);
}

/*
 * Implements decryptBlockBytes on InputOutputHandler object
 * */
static void InputOutputHandlerDecryptBlockBytes(const struct InputOutputHandler* ioh, const KeyExpansion_t* ke_p){
  decryptBlockBytes(ioh->inputCurrentPossition, ke_p, ioh->outputCurrentPossition);
}

/*
 * Implementation of ECB encryption operation mode.
 * */
static void encryptECB__(const KeyExpansion_t* ke_p, struct InputOutputHandler* ioh){
  if(InputOutputHandlerIsSmallerThanBlock(ioh)) return;                         // -Not handling the case size < 16
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

/*
 * Builds KeyExpansion_t and InputOutput objects, then implements ECB encryption operation mode.
 * */
void encryptECB(const uint8_t*const input, size_t size, const uint8_t* keyexpansion, size_t keylenbits, uint8_t*const output){
  ptrKeyExpansion_t ke_p = KeyExpansionFromBytes(keyexpansion, keylenbits);
  struct InputOutputHandler ioh = InputOutputHandlerInitialize(input, output, size);
  encryptECB__(ke_p, &ioh);
  KeyExpansionDelete(&ke_p);
}

/*
 * Implementation of ECB decryption operation mode.
 * */
static void decryptECB__(const KeyExpansion_t* ke_p, struct InputOutputHandler* ioh){
  if(InputOutputHandlerIsSmallerThanBlock(ioh)) return;                         // -Not handling the case size < 16
  InputOutputHandlerDecryptBlockBytes(ioh, ke_p);
  for(size_t i = 1; i < ioh->sizeInBlocks; i++) {
    InputOutputHandlerMoveForwardOneBlock(ioh);
    InputOutputHandlerDecryptBlockBytes(ioh, ke_p);
  }
  // -Handling the case where input size is not multiple of 16. This is not specified in the NIST standard.
  if(ioh->tailSize != 0) {
    decryptBlockBytes(ioh->inputCurrentPossition + ioh->tailSize, ke_p, ioh->outputCurrentPossition + ioh->tailSize);
  }
}

/*
 * Builds KeyExpansion_t and InputOutput objects, then implements ECB decryption operation mode.
 * */
void decryptECB(const uint8_t*const input, size_t size, const uint8_t* keyexpansion, size_t keylenbits, uint8_t*const output){
  ptrKeyExpansion_t ke_p = KeyExpansionFromBytes(keyexpansion, keylenbits);
  struct InputOutputHandler ioh = InputOutputHandlerInitialize(input, output, size);
  decryptECB__(ke_p, &ioh);
  KeyExpansionDelete(&ke_p);
}

/*
 * Build Block_t with input, build Block_t with XORsource, xors both blocks and encrypt the result.
 * */
static void xorEncryptBlockBytes(const uint8_t*const input, const KeyExpansion_t* ke_p, const uint8_t* XORsource, uint8_t* output){
  Block_t* buffer = BlockMemoryAllocationFromBytes(input);
  BlockXORequalBytes(buffer, XORsource);
  encryptBlock(buffer, ke_p, buffer, false);
  bytesFromBlock(buffer, output);
  BlockDelete(&buffer);
}

/*
 * Implements xorEncryptBlockBytes on ioh object.
 * */
static void InputOutputHandlerXorEncryptBlockBytes(const struct InputOutputHandler* ioh, const uint8_t *XORsource, const KeyExpansion_t* ke_p){
  xorEncryptBlockBytes(ioh->inputCurrentPossition, ke_p, XORsource, ioh->outputCurrentPossition);
}

/*
 * Implementation of CBC encryption operation mode.
 * */
static void encryptCBC__(const KeyExpansion_t* ke_p, const uint8_t* IV, struct InputOutputHandler* ioh){
  if(InputOutputHandlerIsSmallerThanBlock(ioh)) return;                         // -Not handling the case size < 16
  const uint8_t* inputPreviousBlock = NULL;
  InputOutputHandlerXorEncryptBlockBytes(ioh, IV, ke_p);                        // -Encryption of the first block.
  for(size_t i = 1; i < ioh->sizeInBlocks; i++) {                               // -Encryption of the rest of the blocks.
    inputPreviousBlock = ioh->inputCurrentPossition;
    InputOutputHandlerMoveForwardOneBlock(ioh);
    InputOutputHandlerXorEncryptBlockBytes(ioh, inputPreviousBlock, ke_p);
  }
  // -Handling the case where input size is not multiple of 16. This is not specified in the NIST standard. Not specified in the NIST standard.
  if(ioh->tailSize != 0) {
      size_t k = ioh->sizeInBlocks*BLOCK_SIZE, i;
      for(i = 0; i < ioh->tailSize; i++,k++) ioh->output[k] ^= inputPreviousBlock[i];
      encryptBlockBytes(ioh->inputCurrentPossition + ioh->tailSize, ke_p, ioh->outputCurrentPossition + ioh->tailSize);
  }
}

/*
 * Builds KeyExpansion_t and InputOutput objects, then implements CBC encryption operation mode.
 * */
void encryptCBC(const uint8_t*const input, size_t size, const uint8_t* keyexpansion, size_t keylenbits, const uint8_t* IV, uint8_t*const output){
  ptrKeyExpansion_t ke_p = KeyExpansionFromBytes(keyexpansion, keylenbits);
  struct InputOutputHandler ioh = InputOutputHandlerInitialize(input, output, size);
  encryptCBC__(ke_p, IV, &ioh);
  KeyExpansionDelete(&ke_p);
}


/*
 * Build Block_t with input, build Block_t with XORsource, xors both blocks and decrypt the result.
 * */
static void decryptXorBlockBytes(const uint8_t*const input, const KeyExpansion_t* ke_p, const uint8_t* XORsource, uint8_t* output){
  Block_t* buffer = BlockMemoryAllocationFromBytes(input);
  decryptBlock(buffer, ke_p, buffer, false);
  BlockXORequalBytes(buffer, XORsource);
  bytesFromBlock(buffer, output);
  BlockDelete(&buffer);
}

/*
 * Implements xorEncryptBlockBytes on ioh object.
 * */
static void InputOutputHandlerDecryptXorBlockBytes(const struct InputOutputHandler* ioh, const uint8_t *XORsource, const KeyExpansion_t* ke_p){
  decryptXorBlockBytes(ioh->inputCurrentPossition, ke_p, XORsource, ioh->outputCurrentPossition);
}

/*
 * Implementation of CBC decryption operation mode.
 * */
static void decryptCBC__(const KeyExpansion_t* ke_p, const uint8_t* IV, struct InputOutputHandler* ioh) {
  if(InputOutputHandlerIsSmallerThanBlock(ioh)) return;                         // -Not handling the case size < 16
  uint8_t prevBlockCopy[BLOCK_SIZE];
  uint8_t currBlockCopy[BLOCK_SIZE];
  memcpy(prevBlockCopy, ioh->inputCurrentPossition, BLOCK_SIZE);                // Saving previous block to xor it with the next one
  InputOutputHandlerDecryptXorBlockBytes(ioh, IV, ke_p);                        // -Decryption of the first block.
  for(size_t i = 1; i < ioh->sizeInBlocks; i++) {                               // -Encryption of the rest of the blocks.
    InputOutputHandlerMoveForwardOneBlock(ioh);
    memcpy(currBlockCopy, ioh->inputCurrentPossition, BLOCK_SIZE);
    InputOutputHandlerDecryptXorBlockBytes(ioh, prevBlockCopy, ke_p);
    memcpy(prevBlockCopy, currBlockCopy, BLOCK_SIZE);
  }
  // -Handling the case where input size is not multiple of 16. This is not specified in the NIST standard. Not specified in the NIST standard.
  if(ioh->tailSize != 0) {
    decryptBlockBytes(ioh->inputCurrentPossition + ioh->tailSize, ke_p, ioh->outputCurrentPossition + ioh->tailSize);
    size_t k = ioh->sizeInBlocks*BLOCK_SIZE, i;
    for(i = 0; i < ioh->tailSize; i++,k++) ioh->output[k] ^= prevBlockCopy[i];
  }
}

/*
 * Builds KeyExpansion_t and InputOutput objects, then implements CBC decryption operation mode.
 * */
void decryptCBC(const uint8_t*const input, size_t size, const uint8_t* keyexpansion, size_t keylenbits, const uint8_t* IV, uint8_t*const output){
  ptrKeyExpansion_t ke_p = KeyExpansionFromBytes(keyexpansion, keylenbits);
  struct InputOutputHandler ioh = InputOutputHandlerInitialize(input, output, size);
  decryptCBC__(ke_p, IV, &ioh);
  KeyExpansionDelete(&ke_p);
}
