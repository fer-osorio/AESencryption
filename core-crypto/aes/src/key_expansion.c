#include "SBox.h"
#include "word.h"
#include "../include/key_expansion.h"
#include "../include/constants.h"
#include <stdlib.h>
#include <stdio.h>

static size_t getKeyExpansionLengthBlocksfromNk(enum Nk_t Nk){
  return getKeyExpansionLengthWordsfromNk(Nk) / NB;
}

static KeyExpansion_t* KeyExpansionAllocate(enum Nk_t Nk){
  KeyExpansion_t* output = (KeyExpansion_t*)malloc(sizeof(KeyExpansion_t));
  if(output == NULL) return NULL;
  // -Building KeyExpansion_t object
  output->Nk = Nk;
  output->Nr = getNrfromNk(Nk);
  output->wordsSize = getKeyExpansionLengthWordsfromNk(Nk);
  output->blockSize = getKeyExpansionLengthBlocksfromNk(Nk);
  output->dataBlocks = (Block_t*)malloc(output->blockSize*sizeof(Block_t));
  if(output->dataBlocks == NULL) {
      KeyExpansionDestroy(&output);
      return NULL;
  }
  return output;
}

static enum Nk_t keylenbitsToNk(uint32_t keylenbits){
  switch(keylenbits) {
    case Keylenbits128:
      return Nk128;
      break;
    case Keylenbits192:
      return Nk192;
      break;
    case Keylenbits256:
      return Nk256;
      break;
    default:
      return UnknownNk;
  }
}

/*
 * Builds a block using an array of four words.
 * Seeing words as row vectors of a matrix, the resulting block is the transposed of this matrix.
 * Considerations: Assuming that the pointer 'source' is pointing to a valid 4-words array.
 * */
static void BlockFromWords(const Word_t source[], Block_t* output){
  // First row
  output->uint08_[0] = source[0].uint08_[0];
  output->uint08_[4] = source[0].uint08_[1];
  output->uint08_[8] = source[0].uint08_[2];
  output->uint08_[12]= source[0].uint08_[3];
  // Second row
  output->uint08_[1] = source[1].uint08_[0];
  output->uint08_[5] = source[1].uint08_[1];
  output->uint08_[9] = source[1].uint08_[2];
  output->uint08_[13]= source[1].uint08_[3];
  // Third row
  output->uint08_[2] = source[2].uint08_[0];
  output->uint08_[6] = source[2].uint08_[1];
  output->uint08_[10]= source[2].uint08_[2];
  output->uint08_[14]= source[2].uint08_[3];
  // Fourth row
  output->uint08_[3] = source[3].uint08_[0];
  output->uint08_[7] = source[3].uint08_[1];
  output->uint08_[11]= source[3].uint08_[2];
  output->uint08_[15]= source[3].uint08_[3];
}

static void KeyExpansionInitWords(const uint8_t* key, enum Nk_t Nk, Word_t outputKeyExpansion[], bool debug){
  Word_t tmp;
  const size_t KeyExpansionLen = getKeyExpansionLengthWordsfromNk(Nk);
  size_t i;

  for(i = 0; i < Nk; i++) {
    for(size_t j = 0, k = i*WORD_SIZE; j < WORD_SIZE; j++, k++)
      outputKeyExpansion[i].uint08_[j] = key[k];                                // -The first Nk words of the key expansion are the key itself.
  }

  // -Show the construction of the key expansion.
  if(debug) {
    printf(
      "-------------------------------------------------- Key Expansion --------------------------------------------------\n"
      "-------------------------------------------------------------------------------------------------------------------\n"
      "    |               |     After     |     After     |               |   After XOR   |               |     w[i] =   \n"
      " i  |     temp      |   RotWord()   |   SubWord()   |  Rcon[i/Nk]   |   with Rcon   |    w[i-Nk]    |   temp xor   \n"
      "    |               |               |               |               |               |               |    w[i-Nk]   \n"
      "-------------------------------------------------------------------------------------------------------------------\n"
    );
  }

  for(i = Nk; i < KeyExpansionLen; i++) {
    copyWord(&outputKeyExpansion[i - 1], &tmp);                                   // -Guarding against modify things that we don't want to modify.
    if(debug) {
      printf(" %lu",i);
      if(i < 10) printf("  | ");
      else printf(" | ");
      printWord(tmp);
    }
    if((i % Nk) == 0) {                                                         // -i is a multiple of Nk
      RotWord(&tmp);
      if(debug) {
        printf(" | ");
        printWord(tmp);
      }
      SubWord(&tmp);
      if(debug) {
        printf(" | ");
        printWord(tmp);
      }
      if(debug) {
        printf(" | ");
        printWord(Rcon[i/Nk - 1]);
      }
      XORword(tmp, Rcon[i/Nk -1], &tmp);
      if(debug) {
        printf(" | ");
        printWord(tmp);
      }
    } else {
      if(Nk > 6 && (i % Nk) == 4) {
        if(debug) printf(" | ------------- | ");
        SubWord(&tmp);
        if(debug) {
          printWord(tmp);
          printf(" | ------------- | -------------");
        }
      } else {
        if(debug) printf(" |               |               |               |              ");
      }
    }
    if(debug) {
      printf(" | ");
      printWord(outputKeyExpansion[i - Nk]);
    }
    XORword(outputKeyExpansion[i - Nk], tmp, &outputKeyExpansion[i]);
    if(debug) {
      printf(" | ");
      printWord(outputKeyExpansion[i]);
    }
    if(debug) printf("\n");
  }
  if(debug)
    printf(
      "-------------------------------------------------------------------------------------------------------------------\n\n"
    );
  debug = false;
}

enum ExceptionCode KeyExpansionInit(KeyExpansion_t*const output, const uint8_t* key, size_t keylenbits, bool debug){
  if(key == NULL) return NullInput;
  if(output == NULL) return NullOutput;
  enum Nk_t Nk = keylenbitsToNk(keylenbits);
  if(Nk == UnknownNk) return InvalidKeyLength;

  Word_t* buffer = (Word_t*)malloc(output->wordsSize*sizeof(Word_t));
  if(buffer == NULL) return BadAllocation;

  // Writing key expansion on array of words
  KeyExpansionInitWords(key, Nk, buffer, debug);

  // Writing key expansion on the array of Blocks inside KeyExpansion_t object.
  for(size_t i = 0, j = 0; i < output->wordsSize && j < output->blockSize; i += NB, j++){
    BlockFromWords(buffer + i, output->dataBlocks + j);
  }
  free(buffer);

  return NoException;
}

KeyExpansion_t* KeyExpansionCreate(const uint8_t* key, size_t keylenbits, bool debug){
  enum Nk_t Nk = keylenbitsToNk(keylenbits);
  if(Nk == UnknownNk) {
    return NULL;
  }

  KeyExpansion_t* output = KeyExpansionAllocate(Nk);
  if(output == NULL) return NULL;
  KeyExpansionInit(output, key, keylenbits, debug);

  return output;
}

KeyExpansion_t* KeyExpansionCreateZero(size_t keylenbits){
  enum Nk_t Nk = keylenbitsToNk(keylenbits);
  if(Nk == UnknownNk) {
    return NULL;
  }

  KeyExpansion_t* output = KeyExpansionAllocate(Nk);
  if(output == NULL) return NULL;
  const uint8_t tmp[BLOCK_SIZE] = {0};
  for(size_t i = 0; i < output->blockSize; i++){
    BlockFromBytes(output->dataBlocks + i, tmp);
  }
  return output;
}

void KeyExpansionDestroy(KeyExpansion_t** ke_pp){
  KeyExpansion_t* ke_p = *ke_pp;
  if(ke_p != NULL){
    if(ke_p->dataBlocks != NULL) {
      free(ke_p->dataBlocks);
      ke_p->dataBlocks = NULL;                                                    // Signaling that the memory has been freed.
    }
    free(ke_p);
    *ke_pp = NULL;                                                                // Signaling that the memory has been freed.
  }
}

void KeyExpansionWriteToBytes(const KeyExpansion_t* source, uint8_t* dest){
  for(size_t i = 0, j = 0; i < source->blockSize; i++, j += BLOCK_SIZE){
    BytesFromBlock(source->dataBlocks + i, dest + j);
  }
}

enum ExceptionCode KeyExpansionReadFromBytes(KeyExpansion_t*const output, const uint8_t input[]){
  if(input == NULL) return NullInput;
  if(output == NULL) return NullOutput;
  for(size_t i = 0, j = 0; i < output->blockSize; i++, j += BLOCK_SIZE){
    BlockFromBytes(output->dataBlocks + i, input + j);
  }
  return NoException;
}

enum ExceptionCode KeyExpansionInitWrite(const uint8_t* key, size_t keylenbits, uint8_t* dest, bool debug){
  if(dest == NULL) return NullDestination;
  KeyExpansion_t* ke_p = KeyExpansionCreate(key, keylenbits, false);
  if(ke_p == NULL) return NullKeyExpansion;
  KeyExpansionWriteToBytes(ke_p, dest);
  KeyExpansionDestroy(&ke_p);
  return NoException;
}

bool compareKeyExpansionBytes(const KeyExpansion_t*const input, const uint8_t bytes[]){
  bool result = true;
  // Constant time comparison. Preventing timing attacks.
  for(size_t i = 0, j = 0; i < input->blockSize; i++, j += BLOCK_SIZE){
    result &= compareBlockBytes(input->dataBlocks + i, bytes + j);
  }
  return result;
}
