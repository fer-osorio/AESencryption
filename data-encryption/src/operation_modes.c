#include"../include/constants.h"
#include"../include/AES.h"
#include"../include/operation_modes.h"
#include<string.h>
#include<time.h>

/*
 * Structure: Handling pointer to input data array
 * Each block has 16 bytes of size
 * Argument tailSize is equal to size % 16
 * Argument currentPossition allows movement through the data array
 * Consider: The data pointed is non-mutable (has no write permission, only read permission)
 */
struct InputStream {
  const uint8_t*const start;
  const size_t size;
  const size_t sizeInBlocks;
  const size_t tailSize;
  const uint8_t* currentPossition;
};

/*
 * Signals if data pointed by ioh->input has a size smaller than BLOCK_SIZE.
 * */
static enum ExceptionCode InputStreamValidate(const struct InputStream* is){
  if(is->start == NULL) return NullInput;
  if(is->size < BLOCK_SIZE) return InvalidInputSize;
  return NoException;
}

/*
 * Initialize struct InputStream instance
 */
static struct InputStream InputStreamInitialize(const uint8_t*const start, const size_t size){
  struct InputStream is = {start, size, size / BLOCK_SIZE, size % BLOCK_SIZE, start};
  return is;
}

/*
 * Move current position of InputStream instance one block forward.
 * Consider: No out-of-bounds checking
 */
static void InputStreamMoveForwardOneBlock(struct InputStream* is){
  is->currentPossition += BLOCK_SIZE;
}

/**
 * @brief Reads BLOCK_SIZE bytes from the data pointed by the current position of the input stream and writes a block with them.
 * @param is The input stream
 * @param dest The block to be written
 */
static void InputStreamReadBlockMoveForward(Block_t* dest, struct InputStream* is){
  BlockWriteFromBytes(is->currentPossition, dest);
  InputStreamMoveForwardOneBlock(is);
}

/*
 * Structure: Handling pointer to output data array
 * Each block has 16 bytes of size
 * Argument tailSize is equal to size % 16
 * Argument currentPossition allows movement through the data array
 * Consider: Data can be written through the pointer currentPossition (Intended only for writing, not reading)
 */
struct OutputStream{
  const uint8_t*const start;
  const size_t size;
  const size_t sizeInBlocks;
  const size_t tailSize;
  uint8_t* currentPossition;
};

/*
 * Initialize struct OutputStream instance
 */
static struct OutputStream OutputStreamInitialize(uint8_t*const start, const size_t size){
  struct OutputStream os = {start, size, size / BLOCK_SIZE, size % BLOCK_SIZE, start};
  return os;
}

/*
 * Move current position of OutputStream instance one block forward.
 * Consider: No out-of-bounds checking
 */
static void OutputStreamMoveForwardOneBlock(struct OutputStream* os){
  os->currentPossition += BLOCK_SIZE;
}

/**
 * @brief Writes BLOCK_SIZE bytes on the bytes pointed by the current position of the output stream using the input Block.
 * @param os The output stream
 * @param input Block where the data comes from
 */
static void OutputStreamWriteBlockMoveForward(struct OutputStream* os, Block_t* origin){
  bytesFromBlock(origin, os->currentPossition);
  OutputStreamMoveForwardOneBlock(os);
}

/**
 * @brief Writes block pointed by buffer, encrypts it using ke_p key expansion and writes the result on the output stream.
 */
static void encryptBlockMoveForward(const KeyExpansion_t* ke_p, struct InputStream* is, Block_t* buffer, struct OutputStream* os){
  InputStreamReadBlockMoveForward(buffer, is);
  encryptBlock(buffer, ke_p, buffer, false);
  OutputStreamWriteBlockMoveForward(os, buffer);
}

/**
 * @brief Writes block pointed by buffer, decrypts it using ke_p key expansion and writes the result on the output stream.
 */
static void decryptBlockMoveForward(const KeyExpansion_t* ke_p, struct InputStream* is, Block_t* buffer, struct OutputStream* os){
  InputStreamReadBlockMoveForward(buffer, is);
  decryptBlock(buffer, ke_p, buffer, false);
  OutputStreamWriteBlockMoveForward(os, buffer);
}

/**
 * @brief Implementation of ECB encryption operation mode. Supposes the input parameters are already validated.
 * */
static void encryptECB__(const KeyExpansion_t* ke_p, struct InputStream* is, struct OutputStream* os){
  Block_t* buffer = BlockMemoryAllocationZero();
  // Encrypting the blocks
  for(size_t i = 0; i < is->sizeInBlocks; i++) {
    encryptBlockMoveForward(ke_p, is, buffer, os);
  }
  BlockDelete(&buffer);
}

/**
 * @brief Builds KeyExpansion_t and InputOutput objects, then implements ECB encryption operation mode.
 * */
enum ExceptionCode encryptECB(const uint8_t*const input, size_t size, const uint8_t* keyexpansion, size_t keylenbits, uint8_t*const output){
  // Validating the existence of the resources
  if(input == NULL) return NullInput;
  if(output == NULL) return NullOutput;
  if(keyexpansion == NULL) return NullSource;
  // Validating resources size
  if(size == 0) return ZeroLength;
  if(size % BLOCK_SIZE != 0) return InvalidInputSize;
  // Creating key expansion
  ptrKeyExpansion_t ke_p = KeyExpansionFromBytes(keyexpansion, keylenbits);
  if(ke_p == NULL) return NullKeyExpansion;
  // Creating streams
  struct InputStream is = InputStreamInitialize(input, size);
  struct OutputStream os = OutputStreamInitialize(output, size);
  // Encryption
  encryptECB__(ke_p, &is, &os);
  KeyExpansionDelete(&ke_p);
  return NoException;
}

/*
 * Implementation of ECB decryption operation mode.
 * */
static void decryptECB__(const KeyExpansion_t* ke_p, struct InputStream* is, struct OutputStream* os){
  Block_t* buffer = BlockMemoryAllocationZero();
  // Encrypting the blocks
  for(size_t i = 0; i < is->sizeInBlocks; i++) {
    decryptBlockMoveForward(ke_p, is, buffer, os);
  }
  BlockDelete(&buffer);
}

/*
 * Builds KeyExpansion_t and InputOutput objects, then implements ECB decryption operation mode.
 * */
enum ExceptionCode decryptECB(const uint8_t*const input, size_t size, const uint8_t* keyexpansion, size_t keylenbits, uint8_t*const output){
  // Validating the existence of the resources
  if(input == NULL) return NullInput;
  if(output == NULL) return NullOutput;
  if(keyexpansion == NULL) return NullSource;
  // Validating resources size
  if(size == 0) return ZeroLength;
  if(size % BLOCK_SIZE != 0) return InvalidInputSize;

  ptrKeyExpansion_t ke_p = KeyExpansionFromBytes(keyexpansion, keylenbits);
  if(ke_p == NULL) return NullKeyExpansion;
  struct InputStream is = InputStreamInitialize(input, size);
  struct OutputStream os = OutputStreamInitialize(output, size);
  decryptECB__(ke_p, &is, &os);
  KeyExpansionDelete(&ke_p);
  return NoException;
}


/**
 * @brief Implementation of CBC encryption operation mode. Supposes the input parameters are already validated.
 * */
static void encryptCBC__(const KeyExpansion_t* ke_p, const uint8_t* IV, struct InputStream* is, struct OutputStream* os){
  const uint8_t* outputPreviousBlock = NULL;
  Block_t* buffer = BlockMemoryAllocationZero();
  size_t i;
  BlockXORequalBytes(buffer, IV);
  encryptBlockMoveForward(ke_p, is, buffer, os);
  outputPreviousBlock = is->currentPossition;
  for(i = 1; i < is->sizeInBlocks; i++) {                               // -Encryption of the rest of the blocks.
    BlockXORequalBytes(buffer, IV);
    encryptBlockMoveForward(ke_p, is, buffer, os);
    outputPreviousBlock = is->currentPossition;
  }
  BlockDelete(&buffer);
}

/*
 * Builds KeyExpansion_t and InputOutput objects, then implements CBC encryption operation mode.
 * */
enum ExceptionCode encryptCBC(const uint8_t*const input, size_t size, const uint8_t* keyexpansion, size_t keylenbits, const uint8_t* IV, uint8_t*const output){
  // Validating resource existence
  if(input  == NULL) return NullInput;
  if(output == NULL) return NullOutput;
  if(IV     == NULL) return NullInitialVector;
  if(keyexpansion == NULL) return NullSource;
  // Validating resource sizes
  if(size == 0) return ZeroLength;
  if(size % BLOCK_SIZE != 0) return InvalidInputSize;
  // Building key expansion
  ptrKeyExpansion_t ke_p = KeyExpansionFromBytes(keyexpansion, keylenbits);
  if(ke_p == NULL) return NullKeyExpansion;
  // Creating streams
  struct InputStream is = InputStreamInitialize(input, size);
  struct OutputStream os = OutputStreamInitialize(output, size);
  // Encryption
  encryptCBC__(ke_p, IV, &is, &os);
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

  size_t i = (ioh_p->sizeInBlocks - 1)*BLOCK_SIZE, j;
  const uint8_t* inputPreviousBlock = NULL;
  Block_t* buffer = BlockMemoryAllocationZero();

  InputOutputHandlerMoveTowards(ioh_p, i);

  // -Handling the case where input size is not multiple of BLOCK_SIZE. This is not specified in the NIST standard. Not specified in the NIST standard.
  if(ioh_p->tailSize != 0) {
    // Decrypting tail block
    BlockWriteFromBytes(ioh_p->inputCurrentPossition + ioh_p->tailSize, buffer);
    decryptBlock(buffer, ke_p, buffer, false);
    bytesFromBlock(buffer, ioh_p->outputCurrentPossition + ioh_p->tailSize);
    // Xor tail
    inputPreviousBlock = ioh_p->inputCurrentPossition;
    InputOutputHandlerMoveForwardOneBlock(ioh_p);
    for(i = 0; i < ioh_p->tailSize; i++) ioh_p->outputCurrentPossition[i] ^= inputPreviousBlock[i];
  }
  j = i >= BLOCK_SIZE ? i - BLOCK_SIZE : 0;
  for(; i >= BLOCK_SIZE; i -= BLOCK_SIZE, j -= BLOCK_SIZE) {                    // -Encryption of the rest of the blocks.
    InputOutputHandlerMoveTowards(ioh_p, i);
    inputPreviousBlock = ioh_p->input + j;
    BlockWriteFromBytes(ioh_p->inputCurrentPossition, buffer);
    decryptBlock(buffer, ke_p, buffer, false);
    BlockXORequalBytes(buffer, inputPreviousBlock);
    bytesFromBlock(buffer, ioh_p->outputCurrentPossition);
  }
  // Decryption of last block.
  BlockWriteFromBytes(ioh_p->input, buffer);                                    // At this point ioh_p->inputCurrentPossition == ioh_p->input
  decryptBlock(buffer, ke_p, buffer, false);
  BlockXORequalBytes(buffer, IV);
  bytesFromBlock(buffer, ioh_p->output);
  BlockDelete(&buffer);
}

/*
 * Builds KeyExpansion_t and InputOutput objects, then implements CBC decryption operation mode.
 * */
enum ExceptionCode decryptCBC(const uint8_t*const input, size_t size, const uint8_t* keyexpansion, size_t keylenbits, const uint8_t* IV, uint8_t*const output){
  if(input == NULL) return NullInput;
  if(size == 0) return ZeroLength;
  if(size < BLOCK_SIZE) return InvalidInputSize;
  if(output == NULL) return NullOutput;
  if(IV == NULL) return NullInitialVector;
  if(keyexpansion == NULL) return NullSource;
  ptrKeyExpansion_t ke_p = KeyExpansionFromBytes(keyexpansion, keylenbits);
  if(ke_p == NULL) return NullKeyExpansion;
  struct InputOutputHandler ioh = InputOutputHandlerInitialize(input, output, size);
  decryptCBC__(ke_p, IV, &ioh);
  KeyExpansionDelete(&ke_p);
  return NoException;
}
