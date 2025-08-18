#include"cipher.h"
#include"operation_modes.h"

void encryptECB(const uint8_t*const input, size_t size, uint8_t*const output){
  if(size == 0) return;
  if(input == NULL) return;
  const uint8_t* currentBlock = input;
  Block bufferIn, bufferOut;
  size_t numBlocks = size >> 4, numBlocks_1 = numBlocks - 1;                    //  numBlocks = size / 16.
  size_t rem = size & 15, i;                                                // -Bytes remaining rem = size % 16

  for(i = 0; i < numBlocks_1; i++) {
    blockFromBytes(currentBlock, &bufferIn);
    encryptBlock(const Block *input, const Block *keyExpansion, Nk nk, Block *output, bool debug);
    currentBlock += BLOCK_SIZE;
    }
  if(rem != 0) {                                                              // -This part of the code is for encrypt input that its size is not multiple of 16.
      encryptBlock(currentBlock);                                         //  This is not specified in the NIST standard.
      encryptBlock(currentBlock + rem);                                   // -Not handling the case size < 16
      return;
  }
  encryptBlock(currentBlock);
}
