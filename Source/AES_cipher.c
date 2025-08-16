#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<stdbool.h>
#include"GF256.h"
#include"AES.hpp"

/************************************* Default values for substitution boxes. This are the values showed in the standard ******************************************/

/*
    Determines the endianess used by the system
*/

static const uint8_t SBox[SBOX_SIZE] = {
	0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
	0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
	0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
	0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
	0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
	0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
	0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
	0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
	0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
	0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
	0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
	0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
	0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
	0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
	0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
	0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

static const uint8_t invSBox[SBOX_SIZE] = {
	0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
	0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
	0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
	0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
	0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
	0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
	0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
	0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
	0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
	0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
	0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
	0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
	0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
	0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
	0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

#define WORD_LEN 4
#define WORD_LEN_SHORTS 2
#define WORD_LASTIND 3                                                          // -Last index of a word
#define WORD_LASTIND_SHORT 1                                                    // -Last index of a word using short's

typedef union Word_ {
  uint8_t  uint08_[WORD_LEN];
  uint16_t uint16_[WORD_LEN_SHORTS];
  uint32_t uint32_;
} Word ;

static bool usingLittleEndian(){
  Word val = {.uint32_ = 1};                                                                // Represents 0x00000001 in hexadecimal
  return val.uint08_[0] == 1;                                                  // Cast the address of the integer to a uint8_t pointer to access individual bytes
}

void printWord(Word w) {
  uint32_t WL_1 = WORD_LEN-1, i;
  printf("[");
  for(i = 0; i < WL_1; i++) printf("%.2X,", (uint32_t)w.uint08_[i]);
  printf("%.2X]", (uint32_t)w.uint08_[i]);
};

void copyWord(const Word* orgin, Word* dest){
  dest->uint32_ = orgin->uint32_;
}

static void RotWord(Word* word) {
  uint8_t temp = word->uint08_[0];                                              // As a byte array, the rotation must be performed to the left, but since integer
  if(usingLittleEndian()) word->uint32_ >>= 8;                                  // types have endianess, the bit rotation must be perform according to it
  else word->uint32_ <<= 8;
  word->uint08_[WORD_LASTIND] = temp;
}

static void SubWord(Word* w) {
  w->uint08_[0] = SBox[w->uint08_[0]];
  w->uint08_[1] = SBox[w->uint08_[1]];
  w->uint08_[2] = SBox[w->uint08_[2]];
  w->uint08_[3] = SBox[w->uint08_[3]];
}

static void XORword(const Word b1, const Word b2, Word* result) {
  result->uint32_ = b1.uint32_ ^ b2.uint32_;
}

#define BLOCK_LEN 16
#define Nb 4                                                                    // AES standard constant, length of blocks in words
#define BLOCK_LEN_INT64 2
typedef union Block_{
    uint8_t  uint08_[BLOCK_LEN];
    Word     word_[Nb];
    uint64_t uint64_[BLOCK_LEN_INT64];
} Block ;

#define BLOCK_OPERATION(res,arg1,arg2,op) \
  res->uint64_[0] = arg1->uint64_[0] op arg2->uint64_[0]; \
  res->uint64_[1] = arg1->uint64_[1] op arg2->uint64_[1];

static const Word Rcon[10] = {						                            // -Notice that the value of the left most byte in polynomial form is 2^i.
  {0x01, 0x00, 0x00, 0x00},
  {0x02, 0x00, 0x00, 0x00},
  {0x04, 0x00, 0x00, 0x00},
  {0x08, 0x00, 0x00, 0x00},
  {0x10, 0x00, 0x00, 0x00},
  {0x20, 0x00, 0x00, 0x00},
  {0x40, 0x00, 0x00, 0x00},
  {0x80, 0x00, 0x00, 0x00},
  {0x1B, 0x00, 0x00, 0x00},
  {0x36, 0x00, 0x00, 0x00}
};

static const Block a = {			                                            // -For MixColumns.
  0x02, 0x03, 0x01, 0x01,
  0x01, 0x02, 0x03, 0x01,
  0x01, 0x01, 0x02, 0x03,
  0x03, 0x01, 0x01, 0x02
};

static const Block aInv = {   				                                    // -For InvMixColumns.
  0x0E, 0x0B, 0x0D, 0x09,
  0x09, 0x0E, 0x0B, 0x0D,
  0x0D, 0x09, 0x0E, 0x0B,
  0x0B, 0x0D, 0x09, 0x0E
};

static void printBlock(const Block* b, const char* rowHeaders[4]) {
  int i, j, temp;
  for(i = 0; i < 4; i++) {
    if(rowHeaders != NULL) printf("%s",rowHeaders[i]);
      printWord(b->word_[i]);
      printf("\n");
    }
}

static void XORblocks(const Block* b1,const Block* b2, Block* result) {
  BLOCK_OPERATION(result,b1,b2,^);
}

static void copyBlock(const Block* source, Block* destination) {
  destination->uint64_[0] = source->uint64_[0];
  destination->uint64_[1] = source->uint64_[1];
}

static void SubBytes(Block* b) {                                                // -Applies a substitution table (S-box) to each uint8_t.
  SubWord(&b->word_[0]);
  SubWord(&b->word_[1]);
  SubWord(&b->word_[2]);
  SubWord(&b->word_[3]);
}

static void ShiftRows(Block* b) {                                               // -Shift rows of the state array by different offset.
  bool isLittleEndian = usingLittleEndian();                                  // isLittleEndian will determine the direction of the shift
                                                                              //
  // Shift of second row
  uint8_t temp1 = b->word_[1].uint08_[0];                                          // As a byte array, the rotation must be performed to the left, but since integer
  if(isLittleEndian) b->word_[1].uint32_ >>= 8;                                 // types have endianess, the bit rotation must be perform according to it
  else b->word_[1].uint32_ <<= 8;
  b->word_[1].uint08_[WORD_LASTIND] = temp1;

  // Shift of third row
  short temp2 = b->word_[2].uint16_[0];
  if(isLittleEndian) b->word_[2].uint32_ >>= 16;
  else b->word_[2].uint32_ <<= 16;
  b->word_[2].uint08_[WORD_LASTIND_SHORT] = temp2;

  // Shift of fourth row
  uint8_t temp3 = b->word_[3].uint08_[WORD_LASTIND];                               // Three shift to the left is equivalent to one shift to the right
  if(isLittleEndian) b->word_[3].uint32_ <<= 8;
  else b->word_[3].uint32_ >>= 8;
  b->word_[3].uint08_[0] = temp3;
}

static uint8_t dotProductWord(const Word* w1, const Word* w2){                  // Classical dot product with vectors of dimension four with coefficients in
  return  multiply[w1->uint08_[0]][w2->uint08_[0]] ^                          // GF(256)
          multiply[w1->uint08_[1]][w2->uint08_[1]] ^
          multiply[w1->uint08_[2]][w2->uint08_[2]] ^
          multiply[w1->uint08_[3]][w2->uint08_[3]];
}

static void wordTimesMatrixA(const Word* w, Word* result){
  result->uint08_[0] = dotProductWord(w, &a.word_[0]);
  result->uint08_[1] = dotProductWord(w, &a.word_[1]);
  result->uint08_[2] = dotProductWord(w, &a.word_[2]);
  result->uint08_[3] = dotProductWord(w, &a.word_[3]);
}

static void transposeBlock(const Block* b, Block* bTranspose){
    // Transposing and coping first column
    bTranspose->word_[0].uint08_[0] = b->word_[0].uint08_[0];
    bTranspose->word_[0].uint08_[1] = b->word_[1].uint08_[0];
    bTranspose->word_[0].uint08_[2] = b->word_[2].uint08_[0];
    bTranspose->word_[0].uint08_[3] = b->word_[3].uint08_[0];
    // Transposing and coping second column
    bTranspose->word_[1].uint08_[0] = b->word_[0].uint08_[1];
    bTranspose->word_[1].uint08_[1] = b->word_[1].uint08_[1];
    bTranspose->word_[1].uint08_[2] = b->word_[2].uint08_[1];
    bTranspose->word_[1].uint08_[3] = b->word_[3].uint08_[1];
    // Transposing and coping third column
    bTranspose->word_[2].uint08_[0] = b->word_[0].uint08_[2];
    bTranspose->word_[2].uint08_[1] = b->word_[1].uint08_[2];
    bTranspose->word_[2].uint08_[2] = b->word_[2].uint08_[2];
    bTranspose->word_[2].uint08_[3] = b->word_[3].uint08_[2];
    // Transposing and coping fourth column
    bTranspose->word_[3].uint08_[0] = b->word_[0].uint08_[3];
    bTranspose->word_[3].uint08_[1] = b->word_[1].uint08_[3];
    bTranspose->word_[3].uint08_[2] = b->word_[2].uint08_[3];
    bTranspose->word_[3].uint08_[3] = b->word_[3].uint08_[3];
}

static void MixColumns(Block* b) {                                              // -Mixes the data within each column of the state array.
    Block bT;
    transposeBlock(b,&bT);
    wordTimesMatrixA(&bT.word_[0], &b->word_[0]);
    wordTimesMatrixA(&bT.word_[1], &b->word_[1]);
    wordTimesMatrixA(&bT.word_[2], &b->word_[2]);
    wordTimesMatrixA(&bT.word_[3], &b->word_[3]);
}

static void AddRoundKey(Block* b, const Block keyExpansion[], size_t round) {          // -Combines a round key with the state.
    b->uint64_[0] ^= keyExpansion[round].uint64_[0];                        // -Each block has a 2-uint64 representation
    b->uint64_[1] ^= keyExpansion[round].uint64_[1];
}

/*auto printBlockRow = [] (const char blk[BLOCK_LEN], int row) -> void {
	        unsigned int temp = 0;
            std::cout << '[';
	        for(int i = 0; i < BLOCK_LEN; i += 4) {
	            temp = 0xFF & blk[row + i];
		        if(temp < 16) std::cout << '0';
		        printf("%X", temp);
		        if(i != 12) std::cout << ",";
	        }
	        std::cout << ']';
	    };*/

static void encryptBlock(Block* block, const Block keyExpansion[], size_t Nr) {
  int i, j;
  bool debug = false;                                                           // -True to show every encryption step.
  // -Debugging purposes. Columns of the debugging table.
  Block* SOR;                                                                   // Start of round
  Block* ASB;                                                                   // After SubBytes
  Block* ASR;                                                                   // After ShiftRows
  Block *AMC;                                                                   // After MixColumns
  SOR = ASB = ASR = AMC = NULL;

  if(debug) {
    SOR = (Block*)malloc((Nr+2)*sizeof(Block));
    AMC = (Block*)malloc((Nr - 1)*sizeof(Block));
    ASB = (Block*)malloc(Nr*sizeof(Block));
    ASR = (Block*)malloc(Nr*sizeof(Block));
  }

  if(debug) copyBlock(block,SOR);                                               // Equivalent to copyBlock(block,&SOR[0])
  AddRoundKey(block, keyExpansion, 0);
  if(debug) copyBlock(block,SOR + 1);                                           // Equivalent to copyBlock(block,&SOR[1])

  for(i = 1; i < Nr; i++) {
    SubBytes(block);
    if(debug) copyBlock(block, ASB + (i-1));
    //if(debug) for(j = 0; j < BLOCK_LEN; j++) ASB[((i - 1) << 4) + j] = block->uint08_[j];

    ShiftRows(block);
    if(debug) copyBlock(block, ASR + (i-1));
    //if(debug) for(j = 0; j < BLOCK_LEN; j++) ASR[((i - 1) << 4) + j] = block->uint08_[j];

    MixColumns(block);
    if(debug) copyBlock(block, AMC + (i-1));
    //if(debug) for(j = 0; j < BLOCK_LEN; j++) AMC[((i - 1) << 4) + j] = block->uint08_[j];

    AddRoundKey(block, keyExpansion, i);
    if(debug) copyBlock(block, SOR + (i+1));
    //if(debug) for(j = 0; j < BLOCK_LEN; j++) SOR[((i + 1) << 4) + j] = block->uint08_[j];
  }
  SubBytes(block);
  if(debug) copyBlock(block, ASB + (i-1));
  //if(debug) for(j = 0; j < BLOCK_LEN; j++) ASB[((i - 1) << 4) + j] = block->uint08_[j];

  ShiftRows(block);
  if(debug) copyBlock(block, ASR + (i-1));
  //if(debug) for(j = 0; j < BLOCK_LEN; j++) ASR[((i - 1) << 4) + j] = block->uint08_[j];

  AddRoundKey(block, keyExpansion, i);
  if(debug) copyBlock(block, SOR + (i-1));
  //if(debug) for(j = 0; j < BLOCK_LEN; j++) SOR[((i + 1) << 4) + j] = block->uint08_[j];

  if(debug) {
    printf(
      "---------------------------------------- Cipher ----------------------------------------\n"
      "----------------------------------------------------------------------------------------\n"
      " Round   |    Start of   |     After     |     After     |     After     |   Round key  \n"
      " Number  |     round     |    SubBytes   |   ShiftRows   |   MixColumns  |    value     \n"
      "         |               |               |               |               |              \n"
      "----------------------------------------------------------------------------------------\n"
    );

    for(i = 0; i < 4; i++) {
      if(i == 1) printf(" input  ");
      else printf("        ");
      printf(" | ");
      printWord(SOR[0].word_[i]);
      //printBlockRow(SOR, i);
      printf(" |               |               |               | ");
      printWord(keyExpansion[0].word_[i]);
      printf("\n");
    }
    printf("\n");

    for(i = 1; i <= Nr; i++) {
      for(j = 0; j < Nb; j++) {
        if(j == 1) {
          printf("    ");
          if(i < 10) printf("%d   ", i);
          else printf("%d  ", i);
        }
        else printf("        ");
        printf(" | ");
        printWord(SOR[i].word_[j]);
        //printBlockRow(&SOR[(i << 4)], j);
        printf(" | ");
        printWord(ASB[i-1].word_[j]);
        //printBlockRow(&ASB[((i - 1) << 4)], j);
        printf(" | ");
        printWord(ASR[i-1].word_[j]);
        //printBlockRow(&ASR[((i - 1) << 4)], j);
        printf(" | ");
        if(i < Nr) printWord(AMC[i-1].word_[j]); //printBlockRow(&AMC[((i - 1) << 4)], j);
        else printf("             ");
        printf(" | ");
        printWord(keyExpansion[i].word_[j]);
        printf("\n");
      }
      printf(
        "----------------------------------------------------------------------------------------\n"
      );
    }
    for(i = 0; i < 4; i++) {
      if(i == 1) printf(" output ");
      else printf("        ");
      printf(" | ");
      printWord(block->word_[i]);
      printf(" |               |               |               |               \n");
    }
    printf(
      "----------------------------------------------------------------------------------------\n"
    );
  }
  if(SOR != NULL) { free(SOR); SOR=NULL; }
  if(ASB != NULL) { free(ASB); ASB=NULL; }
  if(ASR != NULL) { free(ASR); ASR=NULL; }
  if(AMC != NULL) { free(AMC); AMC=NULL; }
  debug = false;
}

static void InvShiftRows(Block* b) {                                            // -Shift rows of the state array by different offset.
  bool isLittleEndian = usingLittleEndian();                                  // isLittleEndian will determine the direction of the shift

  // Shift of second row
  uint8_t temp1 = b->word_[1].uint08_[WORD_LASTIND];                                          // As a byte array, the rotation must be performed to the left, but since integer
  if(isLittleEndian) b->word_[1].uint32_ <<= 8;                               // types have endianess, the bit rotation must be perform according to it
  else b->word_[1].uint32_ >>= 8;
  b->word_[1].uint08_[0] = temp1;

  // Shift of third row
  short temp2 = b->word_[2].uint16_[WORD_LASTIND_SHORT];
  if(isLittleEndian) b->word_[2].uint32_ <<= 16;
  else b->word_[2].uint32_ >>= 16;
  b->word_[2].uint08_[0] = temp2;

  // Shift of fourth row
  uint8_t temp3 = b->word_[3].uint08_[0];                               // Three shift to the left is equivalent to one shift to the right
  if(isLittleEndian) b->word_[3].uint32_ >>= 8;
  else b->word_[3].uint32_ <<= 8;
  b->word_[3].uint08_[WORD_LASTIND] = temp3;
}

static void InvSubWord(Word* w) {
    w->uint08_[0] = invSBox[w->uint08_[0]];
    w->uint08_[1] = invSBox[w->uint08_[1]];
    w->uint08_[2] = invSBox[w->uint08_[2]];
    w->uint08_[3] = invSBox[w->uint08_[3]];
}

static void InvSubBytes(Block* b) {                                                // -Applies a substitution table (S-box) to each uint8_t.
    InvSubWord(&b->word_[0]);
    InvSubWord(&b->word_[1]);
    InvSubWord(&b->word_[2]);
    InvSubWord(&b->word_[3]);
}

static void wordTimesMatrixInvA(const Word* w, Word* result){
    result->uint08_[0] = dotProductWord(w, &aInv.word_[0]);
    result->uint08_[1] = dotProductWord(w, &aInv.word_[1]);
    result->uint08_[2] = dotProductWord(w, &aInv.word_[2]);
    result->uint08_[3] = dotProductWord(w, &aInv.word_[3]);
}

static void InvMixColumns(Block* b) {                                              // -Mixes the data within each column of the state array.
    Block bT;
    transposeBlock(b,&bT);
    wordTimesMatrixInvA(&bT.word_[0], &b->word_[0]);
    wordTimesMatrixInvA(&bT.word_[1], &b->word_[1]);
    wordTimesMatrixInvA(&bT.word_[2], &b->word_[2]);
    wordTimesMatrixInvA(&bT.word_[3], &b->word_[3]);
}

void decryptBlock(Block* block, const Block keyExpansion[], size_t Nr) {
    size_t i = Nr;
	AddRoundKey(block, keyExpansion, i);
	for(i--; i > 0; i--) {
		InvShiftRows(block);
		InvSubBytes(block);
		AddRoundKey(block, keyExpansion, i);
		InvMixColumns(block);
	}
	InvShiftRows(block);
	InvSubBytes(block);
	AddRoundKey(block,keyExpansion, 0);
}

static void build_KeyExpansion(const Word key[], size_t Nk, size_t Nr, Word keyExpansion[]){
  Word tmp;                                                                   // (Nr+1)*16
  const size_t NkBytes = Nk << 2;
  const size_t keyExpLen = Nb*(Nr+1);
  int i;

  for(i = 0; i < Nk; i++) keyExpansion[i] = key[i];                           // -The first Nk words of the key expansion are the key itself. // Nk * 4

  bool debug = false;                                                         // -Show the construction of the key expansion.
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

  for(i = Nk; i < keyExpLen; i++) {
    copyWord(&keyExpansion[i - 1], &tmp);                                     // -Guarding against modify things that we don't want to modify.
    if(debug) {
      printf(" %d",i);
      if(i < 10) printf("  | ");
      else printf(" | ");
      printWord(tmp);
    }
    if((i % Nk) == 0) {                                                     // -i is a multiple of Nk, witch value is 8
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
      printWord(keyExpansion[i - Nk]);
    }
    XORword(keyExpansion[i - Nk], tmp, &keyExpansion[i]);
    if(debug) {
      printf(" | ");
      printWord(keyExpansion[i]);
    }
    if(debug) printf("\n");
  }
  if(debug)
    printf(
      "-------------------------------------------------------------------------------------------------------------------\n\n"
    );
  debug = false;
}

/*using namespace AES;

void Cipher::create_KeyExpansion() {
    char temp[4];                                                               // (Nr+1)*16
	int NkBytes = this->Nk << 2, i;                                                   // -The first Nk words of the key expansion are the key itself. // Nk * 4

	if(this->keyExpansion == NULL) this->keyExpansion = new char[this->keyExpLen];
	for(i = 0; i < NkBytes; i++) this->keyExpansion[i] = this->key.keyBytes[i];

    bool debug = false;                                                         // -Show the construction of the key expansion.
	if(debug) {
	    std::cout <<
	    "-------------------------------------------------- Key Expansion --------------------------------------------------\n"
	    "-------------------------------------------------------------------------------------------------------------------\n"
	    "    |               |     After     |     After     |               |   After XOR   |               |     w[i] =   \n"
        " i  |     temp      |   RotWord()   |   SubWord()   |  Rcon[i/Nk]   |   with Rcon   |    w[i-Nk]    |   temp xor   \n"
        "    |               |               |               |               |               |               |    w[i-Nk]   \n"
        "-------------------------------------------------------------------------------------------------------------------\n";
	}

	for(i = this->Nk; i < this->keyExpLen; i++) {
		CopyWord(&(this->keyExpansion[(i - 1) << 2]), temp);                          // -Guarding against modify things that we don't want to modify.
        if(debug) {
            std::cout << " " << i;
            i < 10 ? std::cout << "  | " : std::cout << " | ";
		    printWord(temp);
        }
		if((i % this->Nk) == 0) {                                                     // -i is a multiple of Nk, witch value is 8
			RotWord(temp);
			if(debug) {
			    std::cout << " | ";
			    printWord(temp);
			}
			SubWord(temp);
			if(debug) {
			    std::cout << " | ";
			    printWord(temp);
			}
			if(debug) {
			    std::cout << " | ";
			    printWord(Rcon[i/this->Nk - 1]);
			}
			XORword(temp, Rcon[i/this->Nk -1], temp);
			if(debug) {
			    std::cout << " | ";
			    printWord(temp);
			}
		} else {
		    if(this->Nk > 6 && (i % this->Nk) == 4) {
		        if(debug) std::cout << " | ------------- | ";
			    SubWord(temp);
			    if(debug) {
			        printWord(temp);
			        std::cout << " | ------------- | -------------";
			    }
		    } else {
		        if(debug)
		            std::cout << " |               |               |               |              ";
		    }
		}
		if(debug) {
			std::cout << " | ";
			printWord(&(this->keyExpansion[(i - this->Nk) << 2]));
		}
		XORword(&(this->keyExpansion[(i - this->Nk) << 2]),temp, &(this->keyExpansion[i << 2]));
		if(debug) {
			std::cout << " | ";
			printWord(&(this->keyExpansion[i << 2]));
		}
		if(debug )std::cout << '\n';
	}
	if(debug) std::cout << "--------------------------------------------------"
	"-----------------------------------------------------------------\n\n";
	debug = false;
}*/
