#include "word.h"
#include "../include/block.h"
#include <stdlib.h>

enum ExceptionCode BlockFromBytes(Block_t*const output, const uint8_t*const input){
  if(input == NULL)  return NullInput;
  if(output == NULL) return NullOutput;
  // First column
  output->uint08_[0] = input[0];
  output->uint08_[4] = input[1];
  output->uint08_[8] = input[2];
  output->uint08_[12]= input[3];
  // Second column
  output->uint08_[1] = input[4];
  output->uint08_[5] = input[5];
  output->uint08_[9] = input[6];
  output->uint08_[13]= input[7];
  // Third column
  output->uint08_[2] = input[8];
  output->uint08_[6] = input[9];
  output->uint08_[10]= input[10];
  output->uint08_[14]= input[11];
  // Fourth column
  output->uint08_[3] = input[12];
  output->uint08_[7] = input[13];
  output->uint08_[11]= input[14];
  output->uint08_[15]= input[15];

  return NoException;
}

Block_t* BlockCreate(const uint8_t source[]){
  Block_t* output = (Block_t*)malloc(sizeof(Block_t));
  if(output == NULL) return NULL;
  BlockFromBytes(output, source);
  return output;
}

void BlockDestroy(Block_t** blk_pp){
  Block_t* blk_p = *blk_pp;
  if(blk_p != NULL) free(blk_p);
  *blk_pp = NULL;
}

void BytesFromBlock(const Block_t* source, uint8_t output[]){
  // First column
  output[0] = source->uint08_[0];
  output[4] = source->uint08_[1];
  output[8] = source->uint08_[2];
  output[12]= source->uint08_[3];
  // Second column
  output[1] = source->uint08_[4];
  output[5] = source->uint08_[5];
  output[9] = source->uint08_[6];
  output[13]= source->uint08_[7];
  // Third column
  output[2] = source->uint08_[8];
  output[6] = source->uint08_[9];
  output[10]= source->uint08_[10];
  output[14]= source->uint08_[11];
  // Fourth column
  output[3] = source->uint08_[12];
  output[7] = source->uint08_[13];
  output[11]= source->uint08_[14];
  output[15]= source->uint08_[15];
}

Block_t* BlockCreateZero(){
  Block_t* output = (Block_t*)malloc(sizeof(Block_t));
  if(output == NULL) return NULL;
  for(size_t i = 0; i < NB; i++) output->word_[i].uint32_ = 0;
  return output;
}

void printBlock(const Block_t* b, const char* rowHeaders[4]) {
  for(size_t i = 0; i < 4; i++) {
    if(rowHeaders != NULL) printf("%s",rowHeaders[i]);
      printWord(b->word_[i]);
      printf("\n");
    }
}

void BlockXORBytes(Block_t* input, const uint8_t byteBlock[]){
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

void BytesXORBlockTo(const uint8_t input[], const Block_t* block, uint8_t output[]){
  output[0] = input[0] ^ block->uint08_[0];
  output[1] = input[1] ^ block->uint08_[4];
  output[2] = input[2] ^ block->uint08_[8];
  output[3] = input[3] ^ block->uint08_[12];
  output[4] = input[4] ^ block->uint08_[1];
  output[5] = input[5] ^ block->uint08_[5];
  output[6] = input[6] ^ block->uint08_[9];
  output[7] = input[7] ^ block->uint08_[13];
  output[8] = input[8] ^ block->uint08_[2];
  output[9] = input[9] ^ block->uint08_[6];
  output[10] = input[10] ^ block->uint08_[10];
  output[11] = input[11] ^ block->uint08_[14];
  output[12] = input[12] ^ block->uint08_[3];
  output[13] = input[13] ^ block->uint08_[7];
  output[14] = input[14] ^ block->uint08_[11];
  output[15] = input[15] ^ block->uint08_[15];
}

bool compareBlockBytes(const Block_t*const input, const uint8_t byteBlock[]){
  bool result = true; // Constant time comparison. Preventing timing attacks
  result &= input->uint08_[0] == byteBlock[0];
  result &= input->uint08_[1] == byteBlock[4];
  result &= input->uint08_[2] == byteBlock[8];
  result &= input->uint08_[3] == byteBlock[12];
  result &= input->uint08_[4] == byteBlock[1];
  result &= input->uint08_[5] == byteBlock[5];
  result &= input->uint08_[6] == byteBlock[9];
  result &= input->uint08_[7] == byteBlock[13];
  result &= input->uint08_[8] == byteBlock[2];
  result &= input->uint08_[9] == byteBlock[6];
  result &= input->uint08_[10] == byteBlock[10];
  result &= input->uint08_[11] == byteBlock[14];
  result &= input->uint08_[12] == byteBlock[3];
  result &= input->uint08_[13] == byteBlock[7];
  result &= input->uint08_[14] == byteBlock[11];
  result &= input->uint08_[15] == byteBlock[15];
  return result;
}
