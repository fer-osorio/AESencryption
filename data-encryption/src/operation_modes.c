#include"../include/constants.h"
#include"../include/AES.h"
#include"../include/operation_modes.h"
#include<string.h>
#include<time.h>

/**
 * @struct Stream
 * @brief Handling pointer to data array intended for input or output stream
 *
 * Each block has 16 bytes of size
 *
 * @warning: Only data stream information. No mutable object with only writing permission.
 */
struct Stream{
  // Convenient-to-know points of the stream.
  const uint8_t*const start;        ///<  Start of stream
  const uint8_t*const end;          ///<  End of stream
  const uint8_t*const lastBlock;    ///<  Points to the last block of the stream (each block has 16 bytes)
  // Stream size information
  const size_t size;                ///<  Stream size
  const size_t sizeInBlocks;        ///<  Stream size in blocks
  const size_t tailSize;            ///<  Non-zero for streams with non-multiple BLOCK_SIZE sizes.
};

/**
 * @brief Initialize struct Stream instance
 * @warning Does not integrate explicit stream validation
 */
static struct Stream StreamInitialize(const uint8_t*const start, const size_t size){
  size_t sizeInBlocks_ = size / BLOCK_SIZE;
  struct Stream is = {
    start,                  // start
    start + size,           // end
    start + sizeInBlocks_,  // lastBlock
    size,                   // size
    sizeInBlocks_,          // sizeInBlocks
    size % BLOCK_SIZE       // tailSize
  };
  return is;
}

/**
 * @brief Signals if data pointed by s->input is NULL or has a size smaller than BLOCK_SIZE.
 * */
static enum ExceptionCode StreamValidate(const struct Stream* s){
  if(s->start == NULL) return NullInput;
  if(s->size < BLOCK_SIZE) return InvalidInputSize;
  return NoException;
}

/**
 * @struct InputSteam structure
 * @brief Handling data arrays as input streams.
 * @warning No writing permission, only reading through currentPossition object
 */
struct InputStream {
  struct Stream info;                 ///< Stream information
  const uint8_t* currentPossition;    ///< For reading operation, pointer to the data intended for reading.
};

/**
 * @brief Initialize struct OutputStream instance
 * @warning Does not integrate explicit stream validation
 */
static struct InputStream InputStreamInitialize(const uint8_t*const start, const size_t size){
  struct InputStream is = {
    StreamInitialize(start, size),
    start
  };
  return is;
}

/**
 * @brief Move current position of InputStream instance one block forward.
 * @warning Does not signal out-of-bounds operations, it only does nothing in those cases
 */
static void InputStreamMoveForwardOneBlock(struct InputStream* is){
  if(is->currentPossition < is->info.lastBlock) is->currentPossition += BLOCK_SIZE;
}

/**
 * @brief Reads BLOCK_SIZE bytes from the data pointed by the current position of the input stream and writes a block with them.
 * @param is The input stream
 * @param dest The block where the read data will be written
 */
static void InputStreamReadBlockMoveForward(Block_t* dest, struct InputStream* is){
  BlockWriteFromBytes(is->currentPossition, dest);
  InputStreamMoveForwardOneBlock(is);
}

/**
 * @struct OutputStream structure
 * @warning Reading and writing permission through the currentPossition pointer (intended for writing).
 */
struct OutputStream{
  struct Stream info;
  uint8_t* currentPossition;    ///< * For writing operation, pointer to the place where the data will be written.
};

/**
 * @brief Initialize struct InputStream instance
 * @warning Does not integrate explicit stream validation
 */
static struct OutputStream OutputStreamInitialize(uint8_t*const start, const size_t size){
  struct OutputStream os = {
    StreamInitialize(start, size),
    start
  };
  return os;
}

/**
 * @brief Move current position of OutputStream instance one block forward.
 * @warning Does not signal out-of-bounds operations, it only does nothing in those cases
 */
static void OutputStreamMoveForwardOneBlock(struct OutputStream* os){
  if(os->currentPossition < os->info.lastBlock) os->currentPossition += BLOCK_SIZE;
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
  for(size_t i = 0; i < is->info.sizeInBlocks; i++) {
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
  for(size_t i = 0; i < is->info.sizeInBlocks; i++) {
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
  // Building key expansion
  ptrKeyExpansion_t ke_p = KeyExpansionFromBytes(keyexpansion, keylenbits);
  if(ke_p == NULL) return NullKeyExpansion;
  // Creating streams
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
  for(i = 1; i < is->info.sizeInBlocks; i++) {                               // -Encryption of the rest of the blocks.
    BlockXORequalBytes(buffer, outputPreviousBlock);
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
