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

static void InputOutputHandlerMoveTowards(struct InputOutputHandler* ioh_p, size_t index){
  ioh_p->inputCurrentPossition = ioh_p->input + index;
  ioh_p->inputCurrentPossition = ioh_p->output + index;
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
 * Takes BLOCK_SIZE bytes, converts to block, decrypts and writes on output.
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
/*static void InputOutputHandlerDecryptBlockBytes(const struct InputOutputHandler* ioh, const KeyExpansion_t* ke_p){
  decryptBlockBytes(ioh->inputCurrentPossition, ke_p, ioh->outputCurrentPossition);
}*/

/*
 * Implementation of ECB encryption operation mode.
 * */
static void encryptECB__(const KeyExpansion_t* ke_p, struct InputOutputHandler* ioh_p){
  if(InputOutputHandlerIsSmallerThanBlock(ioh_p)) return;                         // -Not handling the case size < BLOCK_SIZE
  Block_t* buffer = BlockMemoryAllocationFromBytes(ioh_p->inputCurrentPossition);

  encryptBlock(buffer, ke_p, buffer, false);
  for(size_t i = 1; i < ioh_p->sizeInBlocks; i++) {
    InputOutputHandlerMoveForwardOneBlock(ioh_p);
    BlockWriteFromBytes(ioh_p->inputCurrentPossition, buffer);
    encryptBlock(buffer, ke_p, buffer, false);
    bytesFromBlock (buffer,ioh_p->outputCurrentPossition);
  }
  // -Handling the case where input size is not multiple of BLOCK_SIZE. This is not specified in the NIST standard.
  if(ioh_p->tailSize != 0) {
    BlockWriteFromBytes(ioh_p->inputCurrentPossition + ioh_p->tailSize, buffer);
    encryptBlock(buffer, ke_p, buffer, false);
    bytesFromBlock (buffer,ioh_p->outputCurrentPossition + ioh_p->tailSize);
  }
  BlockDelete(&buffer);
}

/*
 * Builds KeyExpansion_t and InputOutput objects, then implements ECB encryption operation mode.
 * */
enum ExceptionCode encryptECB(const uint8_t*const input, size_t size, const uint8_t* keyexpansion, size_t keylenbits, uint8_t*const output){
  ptrKeyExpansion_t ke_p = KeyExpansionFromBytes(keyexpansion, keylenbits);
  if(ke_p == NULL) return NullKeyExpansion;
  if(input == NULL) return NullInput;
  if(output == NULL) return NullOutput;
  struct InputOutputHandler ioh = InputOutputHandlerInitialize(input, output, size);
  encryptECB__(ke_p, &ioh);
  KeyExpansionDelete(&ke_p);
  return NoException;
}

/*
 * Implementation of ECB decryption operation mode.
 * */
static void decryptECB__(const KeyExpansion_t* ke_p, struct InputOutputHandler* ioh_p){
  if(InputOutputHandlerIsSmallerThanBlock(ioh_p)) return;                       // -Not handling the case size < BLOCK_SIZE
  Block_t* buffer;

  // -Handling the case where input size is not multiple of BLOCK_SIZE. This is not specified in the NIST standard.
  if(ioh_p->tailSize != 0) {
    buffer = BlockMemoryAllocationFromBytes(ioh_p->input + (ioh_p->size - BLOCK_SIZE)); // Go to the end and come bakc one block
    decryptBlock(buffer, ke_p, buffer, false);                                  // Decrypt the "tail block"
    bytesFromBlock(buffer, ioh_p->outputCurrentPossition + (ioh_p->size - BLOCK_SIZE)); // Write on output
    BlockWriteFromBytes(ioh_p->inputCurrentPossition, buffer);                  // Come back to the begining
  } else {
    buffer = BlockMemoryAllocationFromBytes(ioh_p->inputCurrentPossition);
  }
  decryptBlock(buffer, ke_p, buffer, false);
  for(size_t i = 1; i < ioh_p->sizeInBlocks; i++) {
    InputOutputHandlerMoveForwardOneBlock(ioh_p);
    BlockWriteFromBytes(ioh_p->inputCurrentPossition, buffer);
    decryptBlock(buffer, ke_p, buffer, false);
    bytesFromBlock (buffer,ioh_p->outputCurrentPossition);
  }
  BlockDelete(&buffer);
}

/*
 * Builds KeyExpansion_t and InputOutput objects, then implements ECB decryption operation mode.
 * */
enum ExceptionCode decryptECB(const uint8_t*const input, size_t size, const uint8_t* keyexpansion, size_t keylenbits, uint8_t*const output){
  ptrKeyExpansion_t ke_p = KeyExpansionFromBytes(keyexpansion, keylenbits);
  if(ke_p == NULL) return NullKeyExpansion;
  if(input == NULL) return NullInput;
  if(output == NULL) return NullOutput;
  struct InputOutputHandler ioh = InputOutputHandlerInitialize(input, output, size);
  decryptECB__(ke_p, &ioh);
  KeyExpansionDelete(&ke_p);
  return NoException;
}

/*
 * Implementation of CBC encryption operation mode.
 * */
static void encryptCBC__(const KeyExpansion_t* ke_p, const uint8_t* IV, struct InputOutputHandler* ioh_p){
  if(InputOutputHandlerIsSmallerThanBlock(ioh_p)) return;                         // -Not handling the case size < BLOCK_SIZE
  const uint8_t* outputPreviousBlock = NULL;
  Block_t* buffer = BlockMemoryAllocationFromBytes(ioh_p->inputCurrentPossition);
  size_t i;
  BlockXORequalBytes(buffer, IV);
  encryptBlock(buffer, ke_p, buffer, false);
  bytesFromBlock(buffer, ioh_p->outputCurrentPossition);
  for(size_t i = 1; i < ioh_p->sizeInBlocks; i++) {                               // -Encryption of the rest of the blocks.
    outputPreviousBlock = ioh_p->outputCurrentPossition;
    InputOutputHandlerMoveForwardOneBlock(ioh_p);
    BlockWriteFromBytes(ioh_p->inputCurrentPossition, buffer);
    BlockXORequalBytes(buffer, outputPreviousBlock);
    encryptBlock(buffer, ke_p, buffer, false);
    bytesFromBlock(buffer, ioh_p->outputCurrentPossition);
  }
  // -Handling the case where input size is not multiple of BLOCK_SIZE. This is not specified in the NIST standard. Not specified in the NIST standard.
  if(ioh_p->tailSize != 0) {
    const uint8_t* inputTailBlock = ioh_p->inputCurrentPossition + ioh_p->tailSize;
    uint8_t* outputTailBlock = ioh_p->outputCurrentPossition + ioh_p->tailSize;
    outputPreviousBlock = ioh_p->outputCurrentPossition;
    InputOutputHandlerMoveForwardOneBlock(ioh_p);
    for(i = 0; i < ioh_p->tailSize; i++) ioh_p->outputCurrentPossition[i] ^= outputPreviousBlock[i];
    BlockWriteFromBytes(inputTailBlock, buffer);
    encryptBlock(buffer, ke_p, buffer, false);
    bytesFromBlock(buffer, outputTailBlock);
  }
  BlockDelete(&buffer);
}

/*
 * Builds KeyExpansion_t and InputOutput objects, then implements CBC encryption operation mode.
 * */
enum ExceptionCode encryptCBC(const uint8_t*const input, size_t size, const uint8_t* keyexpansion, size_t keylenbits, const uint8_t* IV, uint8_t*const output){
  ptrKeyExpansion_t ke_p = KeyExpansionFromBytes(keyexpansion, keylenbits);
  if(ke_p == NULL) return NullKeyExpansion;
  if(input == NULL) return NullInput;
  if(output == NULL) return NullOutput;
  struct InputOutputHandler ioh = InputOutputHandlerInitialize(input, output, size);
  if(IV == NULL) return NullInitialVector;
  encryptCBC__(ke_p, IV, &ioh);
  KeyExpansionDelete(&ke_p);
  return NoException;
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
static void decryptCBC__(const KeyExpansion_t* ke_p, const uint8_t* IV, struct InputOutputHandler* ioh_p) {
  if(InputOutputHandlerIsSmallerThanBlock(ioh_p)) return;                         // -Not handling the case size < BLOCK_SIZE

  size_t i = ioh_p->sizeInBlocks*BLOCK_SIZE, j = i - BLOCK_SIZE;
  const uint8_t* inputPreviousBlock = NULL;
  Block_t* buffer;

  InputOutputHandlerMoveTowards(ioh_p, i);
  inputPreviousBlock = ioh_p->input + j;

  // -Handling the case where input size is not multiple of BLOCK_SIZE. This is not specified in the NIST standard. Not specified in the NIST standard.
  if(ioh_p->tailSize != 0) {
    buffer  = BlockMemoryAllocationFromBytes(ioh_p->inputCurrentPossition + ioh_p->tailSize);
    decryptBlock(buffer, ke_p, buffer, false);
    bytesFromBlock(buffer, ioh_p->outputCurrentPossition);
    for(size_t i = 0; i < ioh_p->tailSize; i++) ioh_p->outputCurrentPossition[i] ^= inputPreviousBlock[i];
    BlockWriteFromBytes(ioh_p->inputCurrentPossition, buffer);
  } else{
    buffer  = BlockMemoryAllocationFromBytes(ioh_p->inputCurrentPossition);
  }
  decryptBlock(buffer, ke_p, buffer, false);
  BlockXORequalBytes(buffer, inputPreviousBlock);
  bytesFromBlock(buffer, ioh_p->outputCurrentPossition);
  for(; i > 0; i -= BLOCK_SIZE, j = i - BLOCK_SIZE) {                               // -Encryption of the rest of the blocks.
    InputOutputHandlerMoveTowards(ioh_p, i);
    inputPreviousBlock = ioh_p->input + j;
    //InputOutputHandlerMoveForwardOneBlock(ioh_p);
    BlockWriteFromBytes(ioh_p->inputCurrentPossition, buffer);
    decryptBlock(buffer, ke_p, buffer, false);
    BlockXORequalBytes(buffer, inputPreviousBlock);
    bytesFromBlock(buffer, ioh_p->outputCurrentPossition);
  }
  // Decryption of last block.
  BlockWriteFromBytes(ioh_p->inputCurrentPossition, buffer);                    // At this point ioh_p->inputCurrentPossition == ioh_p->input
  decryptBlock(buffer, ke_p, buffer, false);
  BlockXORequalBytes(buffer, IV);
  bytesFromBlock(buffer, ioh_p->outputCurrentPossition);
  BlockDelete(&buffer);
}

/*
 * Builds KeyExpansion_t and InputOutput objects, then implements CBC decryption operation mode.
 * */
enum ExceptionCode decryptCBC(const uint8_t*const input, size_t size, const uint8_t* keyexpansion, size_t keylenbits, const uint8_t* IV, uint8_t*const output){
  ptrKeyExpansion_t ke_p = KeyExpansionFromBytes(keyexpansion, keylenbits);
  if(ke_p == NULL) return NullKeyExpansion;
  if(input == NULL) return NullInput;
  if(output == NULL) return NullOutput;
  struct InputOutputHandler ioh = InputOutputHandlerInitialize(input, output, size);
  if(IV == NULL) return NullInitialVector;
  decryptCBC__(ke_p, IV, &ioh);
  KeyExpansionDelete(&ke_p);
  return NoException;
}
