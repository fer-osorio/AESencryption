#include "../include/constants.h"
#include "../include/AES.h"
#include "../include/operation_modes.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

/**
 * @struct Stream
 * @brief Handling pointer to data array intended for input or output stream
 *
 * Each block has 16 bytes of size
 *
 * @warning: Only data stream information. Not intended for reading or writing.
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
    start + (sizeInBlocks_ > 0 ? (sizeInBlocks_ - 1)*BLOCK_SIZE : 0),  // lastBlock
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
 * @brief Move current position of InputStream instance one block backwards.
 * @warning Does not signal out-of-bounds operations, it only does nothing in those cases
 */
static void InputStreamMoveBackwardsOneBlock(struct InputStream* is){
  if(is->currentPossition > is->info.start)
    is->currentPossition = (const uint8_t*)((size_t)is->currentPossition - BLOCK_SIZE);
}

/**
 * @brief Moves currentPossition towards last block.
 */
static void InputStreamMoveTowardsLastBlock(struct InputStream* is){
  is->currentPossition = is->info.lastBlock;
}

/**
 * @brief Reads BLOCK_SIZE bytes from the data pointed by the current position of the input stream and writes a block with them, then moves one block forward.
 * @param is The input stream
 * @param dest The block where the read data will be written
 */
static void InputStreamReadBlockMoveForward(Block_t* dest, struct InputStream* is){
  BlockWriteFromBytes(is->currentPossition, dest);
  InputStreamMoveForwardOneBlock(is);
}

/**
 * @brief Reads BLOCK_SIZE bytes from the data pointed by the current position of the input stream and writes a block with them, then moves one block backwards.
 * @param is The input stream.
 * @param dest The block where the read data will be written.
 */
static void InputStreamReadBlockMoveBackwards(Block_t* dest, struct InputStream* is){
  BlockWriteFromBytes(is->currentPossition, dest);
  InputStreamMoveBackwardsOneBlock(is);
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
 * @brief Initialize struct OutputStream instance
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
 * @brief Move current position of OutputStream instance one block backwards.
 * @warning Does not signal out-of-bounds operations, it only does nothing in those cases
 */
static void OutputStreamMoveBackwardsOneBlock(struct OutputStream* os){
  if(os->currentPossition > os->info.start)
    os->currentPossition = (uint8_t*)((size_t)os->currentPossition - BLOCK_SIZE);
}

/**
 * @brief Moves currentPossition towards last block.
 */
static void OutputStreamMoveTowardsLastBlock(struct OutputStream* os){
  os->currentPossition =
    (uint8_t*)((size_t)os->info.start + (os->info.sizeInBlocks > 0 ? (os->info.sizeInBlocks - 1)*BLOCK_SIZE : 0));
}

/**
 * @brief Writes BLOCK_SIZE bytes on the bytes pointed by the current position of the output stream using the input Block, then moves forward one block.
 * @param os The output stream
 * @param input Block where the data comes from
 */
static void OutputStreamWriteBlockMoveForward(struct OutputStream* os, Block_t* origin){
  bytesFromBlock(origin, os->currentPossition);
  OutputStreamMoveForwardOneBlock(os);
}

/**
 * @brief Writes BLOCK_SIZE bytes on the bytes pointed by the current position of the output stream using the input Block, then moves backwards one block.
 * @param is The input stream.
 * @param dest The block where the read data will be written.
 */
static void OutputStreamWriteBlockMoveBackwards(const Block_t* source, struct OutputStream* os){
  bytesFromBlock(source, os->currentPossition);
  OutputStreamMoveBackwardsOneBlock(os);
}

/**
 * @brief Writes block pointed by buffer, encrypts it using ke_p key expansion, writes the result on the output stream and moves one block forward.
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
 * @brief Implementation of ECB encryption operation mode.
 * @warning Supposes the input parameters are already validated.
 * */
static void encryptECB__(const KeyExpansion_t* ke_p, struct InputStream* is, struct OutputStream* os){
  Block_t* buffer = BlockMemoryAllocationZero();
  // Encrypting the blocks
  for(size_t i = 0; i < is->info.sizeInBlocks; i++) {
    encryptBlockMoveForward(ke_p, is, buffer, os);
  }
  BlockDelete(&buffer);
}

#define VALIDATE_ENCRYPTION_INPUT_OUTPUT_SOURCES(input,size,keyexpansion,output) \
  if(input == NULL) return NullInput; \
  if(output == NULL) return NullOutput; \
  if(keyexpansion == NULL) return NullSource; \
  if(size == 0) return ZeroLength; \
  if(size % BLOCK_SIZE != 0) return InvalidInputSize;

#define BUILD_KEYEXPANSION_FROMBYTES(ke_p,source) \
  ptrKeyExpansion_t ke_p = KeyExpansionFromBytes(source, keylenbits); \
  if(ke_p == NULL) return NullKeyExpansion;

#define BUILD_STREAMS(is,os) \
  struct InputStream is = InputStreamInitialize(input, size); \
  struct OutputStream os = OutputStreamInitialize(output, size);

/**
 * @brief Builds KeyExpansion_t and InputOutput objects, then implements ECB encryption operation mode.
 * */
enum ExceptionCode encryptECB(const uint8_t*const input, size_t size, const uint8_t* keyexpansion, size_t keylenbits, uint8_t*const output){
  VALIDATE_ENCRYPTION_INPUT_OUTPUT_SOURCES(input,size,keyexpansion,output)
  BUILD_KEYEXPANSION_FROMBYTES(ke_p,keyexpansion)
  BUILD_STREAMS(is,os)
  // Encryption
  encryptECB__(ke_p, &is, &os);
  KeyExpansionDelete(&ke_p);
  return NoException;
}

/**
 * @brief Implementation of ECB decryption operation mode.
 * @warning Supposes the input parameters are already validated.
 * */
static void decryptECB__(const KeyExpansion_t* ke_p, struct InputStream* is, struct OutputStream* os){
  Block_t* buffer = BlockMemoryAllocationZero();
  // Encrypting the blocks
  for(size_t i = 0; i < is->info.sizeInBlocks; i++) {
    decryptBlockMoveForward(ke_p, is, buffer, os);
  }
  BlockDelete(&buffer);
}

/**
 * @brief Builds KeyExpansion_t and InputOutput objects, then implements ECB decryption operation mode.
 * */
enum ExceptionCode decryptECB(const uint8_t*const input, size_t size, const uint8_t* keyexpansion, size_t keylenbits, uint8_t*const output){
  VALIDATE_ENCRYPTION_INPUT_OUTPUT_SOURCES(input,size,keyexpansion,output)
  BUILD_KEYEXPANSION_FROMBYTES(ke_p,keyexpansion)
  BUILD_STREAMS(is,os)
  decryptECB__(ke_p, &is, &os);
  KeyExpansionDelete(&ke_p);
  return NoException;
}

/**
 * @brief Writes block pointed by buffer, xor with xorarg, encrypts it using ke_p and writes the result on the output stream.
 * @warning Moves is and os parameters one block forward
 */
static void xorEncryptMoveForward(const KeyExpansion_t* ke_p, struct InputStream* is, Block_t* buffer, const uint8_t* xorarg, struct OutputStream* os){
  InputStreamReadBlockMoveForward(buffer, is);
  BlockXORequalBytes(buffer, xorarg);
  encryptBlock(buffer, ke_p, buffer, false);
  OutputStreamWriteBlockMoveForward(os, buffer);
}


/**
 * @brief Implementation of CBC encryption operation mode.
 * @warning Supposes the input parameters are already validated.
 * */
static void encryptCBC__(const KeyExpansion_t* ke_p, const uint8_t* IV, struct InputStream* is, struct OutputStream* os){
  const uint8_t* outputPreviousBlock = NULL;
  Block_t* buffer = BlockMemoryAllocationZero();
  size_t i;
  // First step of CBC encryption mode
  xorEncryptMoveForward(ke_p, is, buffer, IV, os);
  outputPreviousBlock = os->info.start;
  for(i = 1; i < is->info.sizeInBlocks; i++) {                               // -Encryption of the rest of the blocks.
    xorEncryptMoveForward(ke_p, is, buffer, outputPreviousBlock, os);
    outputPreviousBlock += BLOCK_SIZE;
  }
  BlockDelete(&buffer);
}

/**
 * @brief Builds KeyExpansion_t and InputOutput objects, then implements CBC encryption operation mode.
 * */
enum ExceptionCode encryptCBC(const uint8_t*const input, size_t size, const uint8_t* keyexpansion, size_t keylenbits, const uint8_t* IV, uint8_t*const output){
  VALIDATE_ENCRYPTION_INPUT_OUTPUT_SOURCES(input,size,keyexpansion,output)
  if(IV == NULL) return NullInitialVector;
  BUILD_KEYEXPANSION_FROMBYTES(ke_p,keyexpansion)
  BUILD_STREAMS(is,os)
  // Encryption
  encryptCBC__(ke_p, IV, &is, &os);
  KeyExpansionDelete(&ke_p);
  return NoException;
}

/**
 * @brief Writes block pointed by buffer, decrypts it using ke_p, xor with xorarg and writes the result on the output stream.
 * @warning Moves is and os parameters one block backwards
 */
static void decryptXorMoveBackwards(const KeyExpansion_t* ke_p, struct InputStream* is, Block_t* buffer, const uint8_t* xorarg,struct OutputStream* os){
  InputStreamReadBlockMoveBackwards(buffer, is);
  decryptBlock(buffer, ke_p, buffer, false);
  BlockXORequalBytes(buffer, xorarg);
  OutputStreamWriteBlockMoveBackwards(buffer, os);
}

/**
 * @brief Implementation of CBC decryption operation mode.
 * @warning Supposes the input parameters are already validated.
 * */
static void decryptCBC__(const KeyExpansion_t* ke_p, const uint8_t* IV, struct InputStream* is, struct OutputStream* os){
  Block_t* buffer = BlockMemoryAllocationZero();
  // Initializing streams
  InputStreamMoveTowardsLastBlock(is);
  OutputStreamMoveTowardsLastBlock(os);
  // Initializing stream for previous block
  const uint8_t* previousBlock = (const uint8_t*)((size_t)is->currentPossition - BLOCK_SIZE);
  for(size_t i = 1; i < is->info.sizeInBlocks; i++) {
    decryptXorMoveBackwards(ke_p, is, buffer, previousBlock, os);
    previousBlock = (const uint8_t*)((size_t)previousBlock - BLOCK_SIZE);
  }
  decryptXorMoveBackwards(ke_p, is, buffer, IV, os);  // Decryption of first block
  BlockDelete(&buffer);
}


/*
 * Builds KeyExpansion_t and InputOutput objects, then implements CBC decryption operation mode.
 * */
enum ExceptionCode decryptCBC(const uint8_t*const input, size_t size, const uint8_t* keyexpansion, size_t keylenbits, const uint8_t* IV, uint8_t*const output){
  VALIDATE_ENCRYPTION_INPUT_OUTPUT_SOURCES(input,size,keyexpansion,output)
  if(IV == NULL) return NullInitialVector;
  BUILD_KEYEXPANSION_FROMBYTES(ke_p,keyexpansion)
  BUILD_STREAMS(is,os)
  // Encryption
  decryptCBC__(ke_p, IV, &is, &os);
  KeyExpansionDelete(&ke_p);
  return NoException;
}

/**
 * @brief Single encryption step for the OFB operation mode.
 *
 * Encrypts block pointed by keystream, then xors is the with the bytes pointed by is->currentPossition. Writes the result in
 * os->currentPossition
 *
 * @param[in] ke_p Pointer to the expanded key schedule
 * @param[in,out] is Input stream from which the plain text will be read
 * @param[in,out] keystream The feed back block utilized for the xoring with the plain text
 * @param[out] os Output stream where the cipher text will be written
 * @warning Moves all the streams parameters (is, os) one block forward. It also supposes a well-initialized keystream.
 */
static void applyOFBencryptionStepMoveForward(const KeyExpansion_t* ke_p, struct InputStream* is, Block_t* keystream, struct OutputStream* os){
  encryptBlock(keystream, ke_p, keystream, false);
  bytesXORBlock(is->currentPossition, keystream, os->currentPossition);
  InputStreamMoveForwardOneBlock(is);
  OutputStreamMoveForwardOneBlock(os);
}


/**
 * @brief Implementation of OFB operation mode for encryption.
 */
static void encryptOFB__(const KeyExpansion_t* ke_p, const uint8_t* IV, struct InputStream* is, struct OutputStream* os){
  Block_t* keystream = BlockMemoryAllocationFromBytes(IV);
  for(size_t i = 0; i < is->info.sizeInBlocks; i++) {           // -Encryption of data stream.
    applyOFBencryptionStepMoveForward(ke_p, is, keystream, os);
  }
  uint8_t tmp[BLOCK_SIZE];
  bytesFromBlock(keystream, tmp);
  for(size_t i = 0; i < is->info.tailSize; i++){                // -Encrypting tail of the stream.
    os->currentPossition[i] = is->currentPossition[i] ^ tmp[i];
  }
  BlockDelete(&keystream);
}

/**
 * @brief Implementation of OFB operation mode for decryption.
 *
 * For OFB, encryption and decryption coincide.
 */
static void decryptOFB__(const KeyExpansion_t* ke_p, const uint8_t* IV, struct InputStream* is, struct OutputStream* os){
  encryptOFB__(ke_p, IV, is, os);
}
