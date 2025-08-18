#include"cipher.h"
#include<stdlib.h>
#include<stdio.h>

#define KEYEXP_MAXLEN 60    // Length in words of the Key Expansion of a 128 bits key; Nb*(Nr+1), Nr = Nk+6

const Word key128[Nk128] = {
  {{0x2b,0x7e,0x15,0x16}},{{0x28,0xae,0xd2,0xa6}},
  {{0xab,0xf7,0x15,0x88}},{{0x09,0xcf,0x4f,0x3c}}
};
const Word key192[Nk192] = {
  {{0x8e,0x73,0xb0,0xf7}},{{0xda,0x0e,0x64,0x52}},
  {{0xc8,0x10,0xf3,0x2b}},{{0x80,0x90,0x79,0xe5}},
  {{0x62,0xf8,0xea,0xd2}},{{0x52,0x2c,0x6b,0x7b}}
};
const Word key256[Nk256] = {
  {{0x60,0x3d,0xeb,0x10}},{{0x15,0xca,0x71,0xbe}},
  {{0x2b,0x73,0xae,0xf0}},{{0x85,0x7d,0x77,0x81}},
  {{0x1f,0x35,0x2c,0x07}},{{0x3b,0x61,0x08,0xd7}},
  {{0x2d,0x98,0x10,0xa3}},{{0x09,0x14,0xdf,0xf4}}
};

void createKeyExpansion(Nk nk, Word* keyExpansionLocation, bool showProcess){
  switch(nk){
    case Nk128:
      build_KeyExpansion(key128, Nk128, keyExpansionLocation, showProcess);
      break;
    case Nk192:
      build_KeyExpansion(key192, Nk192, keyExpansionLocation, showProcess);
      break;
    case Nk256:
      build_KeyExpansion(key256, Nk256, keyExpansionLocation, showProcess);
      break;
  }
}

void displayExpansionOfKey(Nk nk){
  Word keyExpansion[KEYEXP_MAXLEN];
  createKeyExpansion(nk, keyExpansion, true);
}

void blockCipher(const Block* plaintext, Nk nk){
  Word* keyExpansion = (Word*)malloc(keyExpansionLenght(nk)*sizeof(Word));
  Block cipherInput, cipherOutput = {0}, decipherOutput = {0};
  const char* cipherInputRowHeaders[4] = {"       ","Plain  ","Text   ","       "};

  printBlock(plaintext, cipherInputRowHeaders);
  transposeBlock(plaintext, &cipherInput);
  createKeyExpansion(nk, keyExpansion, false);

  encryptBlock(&cipherInput, (Block*)keyExpansion, nk, &cipherOutput, true);
  decryptBlock(&cipherOutput, (Block*)keyExpansion, nk, &decipherOutput);

  const char* decipherOutputRowHeaders[4] = {"            ","Deciphered  ","Text        ","            "};
  printBlock(&decipherOutput, decipherOutputRowHeaders);
  free(keyExpansion);
}

int main(int argc, char* argv[]){
  //Block plaintext128 = {{0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34}};
  printf(
    "key128 length: %lu words\n"
    "key192 length: %lu words\n"
    "key256 length: %lu words\n",
    sizeof(key128), sizeof(key192), sizeof(key256)
  );
  displayExpansionOfKey(Nk128);
  displayExpansionOfKey(Nk192);
  displayExpansionOfKey(Nk256);
  return EXIT_SUCCESS;
}

// gcc -o FIPS197_examples -Wall -ggdb -fno-omit-frame-pointer -O2 FIPS197_examples.c cipher.c
