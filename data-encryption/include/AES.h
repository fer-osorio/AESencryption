#ifndef CIPHER_H
#define CIPHER_H

#include<stdlib.h>
#include<stdbool.h>
#include<stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

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
Block_ptr BlockMemoryAllocationFromBytes(const uint8_t source[]);

/*
 * Free the memory allocated for the object pointed by *blk_pp
 * */
void BlockDelete(Block** blk_pp);

/*
 * Writes 16 bytes using the content of 'source'. The writting is perform column to column, from top to bottom.
 * Consider: It supposes there is enough space pointed by the 'output' pointer.
 * */
void bytesFromBlock(const Block* source, uint8_t output[]);

/*
 * Allocates memory for a block filled with random values.
 * Consider: Not intended for the generation of secure random values for cryptographic application.
 * Consider Allocate memory using malloc.
 * */
Block_ptr BlockMemoryAllocationRandom(unsigned int seed);

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
KeyExpansion_ptr KeyExpansionMemoryAllocationBuild(const uint8_t* key, size_t keylenbits, bool debug);

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
 * The amounth of bytes it uses is Nb*((Nk + 6) + 1), where Nb = 4 and Nk = keylenbits/2^5.
 * Consider: Allocates memory using malloc.
 * */
KeyExpansion_ptr KeyExpansionFromBytes(const uint8_t source[], size_t keylenbits);

/*
 * Returns a pointer of type char* to the first element of the key expansion
 * */
const uint8_t* KeyExpansionReturnBytePointerToData(const KeyExpansion*const ke_p);

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
