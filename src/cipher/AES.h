#ifndef CIPHER_H
#define CIPHER_H

#include<stdlib.h>
#include<stdbool.h>
#include<stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NK128 4
#define NK192 6
#define NK256 8
#define NKMAX 8
#define Nb 4                                                                    // AES standard constant, length of blocks in words
enum Nk_{Nk128 = NK128, Nk192 = NK192, Nk256 = NK256};

#define WORD_SIZE 4
#define WORD_SIZE_SHORTS 2
#define WORD_LASTIND 3                                                          // -Last index of a word
#define WORD_LASTIND_SHORT 1                                                    // -Last index of a word using short's
typedef union Word_ {
  uint8_t  uint08_[WORD_SIZE];
  uint16_t uint16_[WORD_SIZE_SHORTS];
  uint32_t uint32_;
} Word ;

#define BLOCK_SIZE 16
#define BLOCK_SIZE_INT64 2
typedef union Block_{
    uint8_t  uint08_[BLOCK_SIZE];
    Word     word_[Nb];
    uint64_t uint64_[BLOCK_SIZE_INT64];
} Block ;

struct KeyExpansion;
typedef struct KeyExpansion* KeyExpansion_ptr;

/*
 * Creates a Block instance from the bytes pointed by source. Basically it takes pieces of four bytes and creates the columns with them
 * Consider: It will read 16 bytes starting from 'source', no caring about what those bytes represent.
 * */
void blockFromBytes(const uint8_t source[], Block* output);

/*
 * Writes 16 bytes using the content of 'source'. The writting is perform column to column, from top to bottom.
 * Consider: It supposes there is enough space pointed by the 'output' pointer.
 * */
void bytesFromBlock(const Block* source, uint8_t output[]);
void printBlock(const Block* b, const char* rowHeaders[4]);

/*
 * Builds key expansion object and returns a pointer to it.
 * Consider: Allocates memory using malloc.
 * */
KeyExpansion_ptr KeyExpansionBuildNew(const Word key[], enum Nk_ Nk, bool debug);

/*
 * Free the memory allocated for an KeyExpansion object pointed by *ke_pp.
 * */
void KeyExpansionDelete(KeyExpansion_ptr* ke_pp);

void encryptBlock(const Block* input, const KeyExpansion_ptr ke_p, Block* output, bool debug);
void decryptBlock(const Block* input, const KeyExpansion_ptr ke_p, Block* output);

#ifdef __cplusplus
}
#endif

#endif
