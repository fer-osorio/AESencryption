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
#define Nb 4                                                                    // AES standard constant, length of blocks in words
enum Nk_{Nk128 = NK128, Nk192 = NK192, Nk256 = NK256};

#define WORD_SIZE 4
#define BLOCK_SIZE 16

typedef union Word_ Word;
typedef Word* Word_ptr;
typedef union Block_ Block;
typedef Block* Block_ptr;
typedef struct KeyExpansion_ KeyExpansion;
typedef KeyExpansion* KeyExpansion_ptr;

/*
 * Creates a Block instance from the bytes pointed by source. Basically it takes pieces of four bytes and creates the columns with them
 * Consider: It will read 16 bytes starting from 'source', no caring about what those bytes represent.
 * Consider: Allocates memory using malloc.
 * */
Block_ptr BlockFromBytes(const uint8_t source[]);

/*
 * Writes 16 bytes using the content of 'source'. The writting is perform column to column, from top to bottom.
 * Consider: It supposes there is enough space pointed by the 'output' pointer.
 * */
void bytesFromBlock(const Block* source, uint8_t output[]);

/*
 * Prints block in matrix form.
 * Row headers are the 'tags' the user wants to put to each row.
 * */
void printBlock(const Block* b, const char* rowHeaders[4]);

/*
 * This function has the same efect than apply the sequence: b = BlockFromBytes(byteBlock), then XORblocks(input, b, input)
 * */
void BlockXORequalBytes(Block* input, const uint8_t byteBlock[]);

/*
 * Builds key expansion object and returns a pointer to it.
 * Consider: Allocates memory using malloc.
 * */
KeyExpansion_ptr KeyExpansionBuildNew(const uint8_t* key, size_t nk, bool debug);

/*
 * Free the memory allocated for an KeyExpansion object pointed by *ke_pp.
 * */
void KeyExpansionDelete(KeyExpansion** ke_pp);

/*
 * Write the bytes that forms the key expansion object on the location pointed by dest.
 * */
void KeyExpansionWriteBytes(const KeyExpansion* source, uint8_t* dest);

/*
 * Creates KeyExpansion object using the bytes pointed by source.
 * The amounth of bytes it uses is Nb*((Nk + 6) + 1), where Nb = 4.
 * Consider: Allocates memory using malloc.
 * */
KeyExpansion_ptr KeyExpansionFromBytes(const uint8_t source[], size_t nk);

/*
 * Encrypts input block using the key referenced by key_p, the resultant encrypted block is written in output
 * If input == output (they point to the same memory location), the input block is overwritten with the encrypted data
 * */
void encryptBlock(const Block* input, const KeyExpansion* ke_p, Block* output, bool debug);

/*
 * Decrypts input block using the key referenced by key_p, the resultant decrypted block is written in output
 * If input == output (they point to the same memory location), the input block is overwritten with the encrypted data
 * */
void decryptBlock(const Block* input, const KeyExpansion* ke_p, Block* output, bool debug);

#ifdef __cplusplus
}
#endif

#endif
