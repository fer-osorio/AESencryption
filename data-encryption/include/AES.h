#ifndef CIPHER_H
#define CIPHER_H

#ifdef __cplusplus
extern "C" {
#endif

#include"exception_code.h"
#include<stdlib.h>
#include<stdbool.h>
#include<stdint.h>

typedef union Word_ Word_t;
typedef union Block_ Block_t;
typedef struct KeyExpansion_ KeyExpansion_t;

/*
 * Reads BLOCK_SIZE bytes from source and writes the on the block pointed by output.
 * */
enum ExceptionCode BlockFromBytes(Block_t*const output, const uint8_t*const input);

/*
 * Creates a Block instance from the bytes pointed by source. Basically it takes pieces of four bytes and creates the columns with them
 * Consider: It will read BLOCK_SIZE bytes starting from 'source', no caring about what those bytes represent.
 * Consider: Allocates memory using malloc.
 * */
Block_t* BlockCreate(const uint8_t source[]);

/*
 * Free the memory allocated for the object pointed by *blk_pp
 * */
void BlockDestroy(Block_t** blk_pp);

/*
 * Writes BLOCK_SIZE bytes using the content of 'source'. The writting is perform column to column, from top to bottom.
 * Consider: It supposes there is enough space pointed by the 'output' pointer.
 * */
void BytesFromBlock(const Block_t* source, uint8_t output[]);

/*
 * Allocates memory for a block filled with zeros.
 * Consider Allocate memory using malloc.
 * */
Block_t* BlockCreateZero();

/*
 * Prints block in matrix form.
 * Row headers are the 'tags' the user wants to put to each row.
 * */
void printBlock(const Block_t* b, const char* rowHeaders[4]);

/*
 * Rewrites input block with the xor of the same input and the bytes pointed by byteBlock
 * */
void BlockXORBytes(Block_t* input, const uint8_t byteBlock[]);

/*
 * Rewrites input byte block with the xor of the same input and the bytes pointed by byteBlock
 * */
void BytesXORBlockTo(const uint8_t input[], const Block_t* block, uint8_t output[]);

/*
 * Compare blocks with the bytes pointed by byteBlock.
 * */
bool compareBlockBytes(const Block_t*const input, const uint8_t byteBlock[]);

/*
 * Builds key expansion object.
 * */
enum ExceptionCode KeyExpansionInit(KeyExpansion_t*const output, const uint8_t* key, size_t keylenbits, bool debug);

/*
 * Builds key expansion object and returns a pointer to it.
 * Consider: Allocates memory using malloc.
 * */
KeyExpansion_t* KeyExpansionCreate(const uint8_t* key, size_t keylenbits, bool debug);

/*
 * Builds key expansion object with zeros and returns a pointer to it.
 * Consider: Allocates memory using malloc.
 * */
KeyExpansion_t* KeyExpansionCreateZero(size_t keylenbits);

/*
 * Free the memory allocated for an KeyExpansion_t object pointed by *ke_pp.
 * */
void KeyExpansionDestroy(KeyExpansion_t** ke_pp);

/*
 * Write the bytes that forms the key expansion object on the location pointed by dest.
 * This function does not implement key expansion algorithm, just formats the data properly.
 * */
void KeyExpansionWriteToBytes(const KeyExpansion_t* source, uint8_t* dest);

/*
 * Writes KeyExpansion_t object using the bytes pointed by source.
 * The amounth of bytes it uses is Nb*((Nk + 6) + 1), where Nb = 4 and Nk = keylenbits/2^5.
 * */
enum ExceptionCode KeyExpansionReadFromBytes(KeyExpansion_t*const output, const uint8_t input[]);

/*
 * Build key expansion and writes it on the bytes pointed by dest pointer.
 * Consider: Supposes that dest pointer points to a suitable memory location.
 * */
enum ExceptionCode KeyExpansionInitWrite(const uint8_t* key, size_t keylenbits, uint8_t* dest, bool debug);

/*
 * Compare key expansion with the bytes pointed by bytes.
 * */
bool compareKeyExpansionBytes(const KeyExpansion_t*const input, const uint8_t bytes[]);

/*
 * Encrypts input block using the key referenced by key_p, the resultant encrypted block is written in output
 * If input == output (they point to the same memory location), the input block is overwritten with the encrypted data
 * */
enum ExceptionCode encryptBlock(const Block_t* input, const KeyExpansion_t* ke_p, Block_t* output, bool debug);

/*
 * Decrypts input block using the key referenced by key_p, the resultant decrypted block is written in output
 * If input == output (they point to the same memory location), the input block is overwritten with the encrypted data
 * */
enum ExceptionCode decryptBlock(const Block_t* input, const KeyExpansion_t* ke_p, Block_t* output, bool debug);

#ifdef __cplusplus
}
#endif

#endif
