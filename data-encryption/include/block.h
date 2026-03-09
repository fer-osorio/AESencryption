#ifndef BLOCK_H
#define BLOCK_H

#ifdef __cplusplus
extern "C" {
#endif

#include "constants.h"
#include "exception_code.h"
#include <stdint.h>
#include <stdbool.h>

#define WORD_SIZE_SHORTS 2
#define WORD_LASTIND 3                  // Last index of a word
#define WORD_LASTIND_SHORT 1            // Last index of a word using short's

typedef union Word_ {
  uint8_t  uint08_[WORD_SIZE];
  uint16_t uint16_[WORD_SIZE_SHORTS];
  uint32_t uint32_;
} Word_t;

#define BLOCK_SIZE_INT64 2

typedef union Block_ {
  uint8_t  uint08_[BLOCK_SIZE];
  Word_t   word_[NB];
  uint64_t uint64_[BLOCK_SIZE_INT64];
} Block_t;

/*
 * Reads BLOCK_SIZE bytes from source and writes them on the block pointed by output.
 * */
enum ExceptionCode BlockFromBytes(Block_t*const output, const uint8_t*const input);

/*
 * Creates a Block instance from the bytes pointed by source.
 * Consider: Allocates memory using malloc.
 * */
Block_t* BlockCreate(const uint8_t source[]);

/*
 * Free the memory allocated for the object pointed by *blk_pp.
 * */
void BlockDestroy(Block_t** blk_pp);

/*
 * Writes BLOCK_SIZE bytes using the content of 'source', column to column, top to bottom.
 * Consider: It supposes there is enough space pointed by the 'output' pointer.
 * */
void BytesFromBlock(const Block_t* source, uint8_t output[]);

/*
 * Allocates memory for a block filled with zeros.
 * Consider: Allocates memory using malloc.
 * */
Block_t* BlockCreateZero();

/*
 * Prints block in matrix form.
 * Row headers are the 'tags' the user wants to put to each row.
 * */
void printBlock(const Block_t* b, const char* rowHeaders[4]);

/*
 * Rewrites input block with the xor of the same input and the bytes pointed by byteBlock.
 * */
void BlockXORBytes(Block_t* input, const uint8_t byteBlock[]);

/*
 * Writes xor of input bytes and block into output byte buffer.
 * */
void BytesXORBlockTo(const uint8_t input[], const Block_t* block, uint8_t output[]);

/*
 * Compare block with the bytes pointed by byteBlock.
 * */
bool compareBlockBytes(const Block_t*const input, const uint8_t byteBlock[]);

#ifdef __cplusplus
}
#endif

#endif
