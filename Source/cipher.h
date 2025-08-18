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
typedef enum Nk_{Nk128 = NK128, Nk192 = NK192, Nk256 = NK256} Nk;

#define WORD_LEN 4
#define WORD_LEN_SHORTS 2
#define WORD_LASTIND 3                                                          // -Last index of a word
#define WORD_LASTIND_SHORT 1                                                    // -Last index of a word using short's

typedef union Word_ {
  uint8_t  uint08_[WORD_LEN];
  uint16_t uint16_[WORD_LEN_SHORTS];
  uint32_t uint32_;
} Word ;

#define BLOCK_LEN 16
#define BLOCK_LEN_INT64 2
typedef union Block_{
    uint8_t  uint08_[BLOCK_LEN];
    Word     word_[Nb];
    uint64_t uint64_[BLOCK_LEN_INT64];
} Block ;

static const Word Rcon[10] = {						                            // -Notice that the value of the left most byte in polynomial form is 2^i.
  {{0x01, 0x00, 0x00, 0x00}},
  {{0x02, 0x00, 0x00, 0x00}},
  {{0x04, 0x00, 0x00, 0x00}},
  {{0x08, 0x00, 0x00, 0x00}},
  {{0x10, 0x00, 0x00, 0x00}},
  {{0x20, 0x00, 0x00, 0x00}},
  {{0x40, 0x00, 0x00, 0x00}},
  {{0x80, 0x00, 0x00, 0x00}},
  {{0x1B, 0x00, 0x00, 0x00}},
  {{0x36, 0x00, 0x00, 0x00}}
};

static const Block a = {{                                                       // -For MixColumns.
  0x02, 0x03, 0x01, 0x01,
  0x01, 0x02, 0x03, 0x01,
  0x01, 0x01, 0x02, 0x03,
  0x03, 0x01, 0x01, 0x02
}};

static const Block aInv = {{                                                    // -For InvMixColumns.
  0x0E, 0x0B, 0x0D, 0x09,
  0x09, 0x0E, 0x0B, 0x0D,
  0x0D, 0x09, 0x0E, 0x0B,
  0x0B, 0x0D, 0x09, 0x0E
}};

/*
 * Creates a Block instance from the bytes pointed by source. Basically it takes pieces of four bytes and creates the columns with them
 * Consider: It will read 16 bytes starting from 'source', no caring about what those bytes represent.
 * */
void blockFromBytes(const uint8_t source[], Block* output);
void printBlock(const Block* b, const char* rowHeaders[4]);
void transposeBlock(const Block* source, Block* result);
size_t keyExpansionLenght(Nk nk);
void build_KeyExpansion(const Word key[], Nk nk, Word keyExpansion[], bool debug);
void encryptBlock(const Block* input, const Block keyExpansion[], Nk nk, Block* output, bool debug);
void decryptBlock(Block* input, const Block keyExpansion[], Nk nk, Block* output);

#ifdef __cplusplus
}
#endif

#endif
