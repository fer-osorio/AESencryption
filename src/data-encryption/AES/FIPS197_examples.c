// -This program shows the examples defined in FIPS-197

#include"AES.h"
#include<stdlib.h>
#include<stdio.h>

#define KEYEXP_MAXLEN 60    // Length in words of the Key Expansion of a 128 bits key; Nb*(Nr+1), Nr = Nk+6

/*******************************************************************************
 * Keys for key expansion examples
 * *****************************************************************************/

#define Nk128bytes 16
#define Nk192bytes 24
#define Nk256bytes 32

static const uint8_t KEE_key128[Nk128bytes] = {
  0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
  0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
};
static const uint8_t KEE_key192[Nk192bytes] = {
  0x8e,0x73,0xb0,0xf7,0xda,0x0e,0x64,0x52,
  0xc8,0x10,0xf3,0x2b,0x80,0x90,0x79,0xe5,
  0x62,0xf8,0xea,0xd2,0x52,0x2c,0x6b,0x7b
};
static const uint8_t KEE_key256[Nk256bytes] = {
  0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
  0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
  0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
  0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
};

/******************************************************************************/

/*******************************************************************************
 * Plain text for example vectors
 * ****************************************************************************/

static const uint8_t EV_key128[Nk128bytes] = {
  0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
  0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
};
static const uint8_t EV_key192[Nk192bytes] = {
  0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
  0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
  0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17
};
static const uint8_t EV_key256[Nk256bytes] = {
  0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
  0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
  0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
  0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
};

/******************************************************************************/

/*******************************************************************************
 * Plain text for example vectors
 * ****************************************************************************/

static uint8_t EV_plainText00[BLOCK_SIZE] = {
  0x00,0x11,0x22,0x33,
  0x44,0x55,0x66,0x77,
  0x88,0x99,0xaa,0xbb,
  0xcc,0xdd,0xee,0xff
};

/******************************************************************************/

static void displayExpansionOfKey(enum Nk_ Nk){
  KeyExpansion_ptr ke_p;
  printf("\n---------------------------------- Displaying key expansion proccess. Nk = %d. -------------------------------------\n", Nk);
  switch(Nk){
    case Nk128:
      ke_p = KeyExpansionBuildNew(KEE_key128, Nk128, true);
      break;
    case Nk192:
      KeyExpansionBuildNew(KEE_key192, Nk192, true);
      break;
    case Nk256:
      KeyExpansionBuildNew(KEE_key256, Nk256, true);
      break;
  }
  KeyExpansionDelete(&ke_p);
}

static void blockCipher(const Block* plaintext, size_t nk, const uint8_t* key){
  KeyExpansion_ptr ke_p = KeyExpansionBuildNew(key, nk, false);
  const uint8_t BlockZero[BLOCK_SIZE] = {0};
  Block_ptr cipherOutput = BlockFromBytes(BlockZero);
  Block_ptr decipherOutput = BlockFromBytes(BlockZero);

  printf("\n--------------------------- Displaying encryption proccess. ----------------------------\n");
  encryptBlock(plaintext, ke_p, cipherOutput, true);

  printf("\n--------------------------- Displaying decryption proccess. ----------------------------\n");
  decryptBlock(cipherOutput, ke_p, decipherOutput, true);

  KeyExpansionDelete(&ke_p);
  free(cipherOutput);
  free(decipherOutput);
}

int main(int argc, char* argv[]){
  Block_ptr plainText00blk = BlockFromBytes(EV_plainText00);

  displayExpansionOfKey(Nk128);
  displayExpansionOfKey(Nk192);
  displayExpansionOfKey(Nk256);

  blockCipher(plainText00blk, 128, EV_key128);
  blockCipher(plainText00blk, 192, EV_key192);
  blockCipher(plainText00blk, 256, EV_key256);

  free(plainText00blk);

  return EXIT_SUCCESS;
}

// gcc -o FIPS197_examples -Wall -ggdb -fno-omit-frame-pointer -O2 FIPS197_examples.c AES.c
