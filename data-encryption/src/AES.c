#include "SBox.h"
#include "GF256.h"
#include "word.h"
#include "../include/AES.h"
#include <stdio.h>
#include <stdlib.h>

static const Block_t a = {{                                                       // -For MixColumns.
  0x02, 0x03, 0x01, 0x01,
  0x01, 0x02, 0x03, 0x01,
  0x01, 0x01, 0x02, 0x03,
  0x03, 0x01, 0x01, 0x02
}};

static const Block_t aInv = {{                                                    // -For InvMixColumns.
  0x0E, 0x0B, 0x0D, 0x09,
  0x09, 0x0E, 0x0B, 0x0D,
  0x0D, 0x09, 0x0E, 0x0B,
  0x0B, 0x0D, 0x09, 0x0E
}};

static void copyBlock(const Block_t* source, Block_t* destination) {
  destination->uint64_[0] = source->uint64_[0];
  destination->uint64_[1] = source->uint64_[1];
}

static void XORblocks(const Block_t* b1, const Block_t* b2, Block_t* result) {
  result->uint64_[0] = b1->uint64_[0] ^ b2->uint64_[0];
  result->uint64_[1] = b1->uint64_[1] ^ b2->uint64_[1];
}

static void AddRoundKey(Block_t* b, const Block_t keyExpansion[], size_t round) {   // -Combines a round key with the state.
  XORblocks(b, keyExpansion+round, b);
}

static void SubBytes(Block_t* b) {                                                // -Applies a substitution table (S-box) to each uint8_t.
  SubWord(&b->word_[0]);
  SubWord(&b->word_[1]);
  SubWord(&b->word_[2]);
  SubWord(&b->word_[3]);
}

static void InvSubBytes(Block_t* b) {                                             // -Applies a substitution table (S-box) to each uint8_t.
  InvSubWord(&b->word_[0]);
  InvSubWord(&b->word_[1]);
  InvSubWord(&b->word_[2]);
  InvSubWord(&b->word_[3]);
}

static void ShiftRows(Block_t* b) {                                               // -Shift rows of the state array by different offset.
#if ENDIAN_UNKNOWN
  if(using_little_endian == -1)
    using_little_endian = usingLittleEndian();                                    // using_little_endian will determine the direction of the shift
#endif
  // Shift of second row
  uint8_t temp1 = b->word_[1].uint08_[0];                                        // As a byte array, the rotation must be performed to the left, but since integer
#if ENDIAN_UNKNOWN
  if(using_little_endian) b->word_[1].uint32_ >>= 8;                             // types have endianess, the bit rotation must be performed according to it
  else b->word_[1].uint32_ <<= 8;
#elif IS_LITTLE_ENDIAN
  b->word_[1].uint32_ >>= 8;
#else
  b->word_[1].uint32_ <<= 8;
#endif
  b->word_[1].uint08_[WORD_LASTIND] = temp1;

  // Shift of third row
  uint16_t temp2 = b->word_[2].uint16_[0];
#if ENDIAN_UNKNOWN
  if(using_little_endian) b->word_[2].uint32_ >>= 16;
  else b->word_[2].uint32_ <<= 16;
#elif IS_LITTLE_ENDIAN
  b->word_[2].uint32_ >>= 16;
#else
  b->word_[2].uint32_ <<= 16;
#endif
  b->word_[2].uint16_[WORD_LASTIND_SHORT] = temp2;

  // Shift of fourth row
  uint8_t temp3 = b->word_[3].uint08_[WORD_LASTIND];                             // Three shift to the left is equivalent to one shift to the right
#if ENDIAN_UNKNOWN
  if(using_little_endian) b->word_[3].uint32_ <<= 8;
  else b->word_[3].uint32_ >>= 8;
#elif IS_LITTLE_ENDIAN
  b->word_[3].uint32_ <<= 8;
#else
  b->word_[3].uint32_ >>= 8;
#endif
  b->word_[3].uint08_[0] = temp3;
}

static void InvShiftRows(Block_t* b) {                                            // -Shift rows of the state array by different offset.
#if ENDIAN_UNKNOWN
  if(using_little_endian == -1)
    using_little_endian = usingLittleEndian();                                    // using_little_endian will determine the direction of the shift
#endif

  // Shift of second row
  uint8_t temp1 = b->word_[1].uint08_[WORD_LASTIND];                             // As a byte array, the rotation must be performed to the left, but since integer
#if ENDIAN_UNKNOWN
  if(using_little_endian) b->word_[1].uint32_ <<= 8;                             // types have endianess, the bit rotation must be performed according to it
  else b->word_[1].uint32_ >>= 8;
#elif IS_LITTLE_ENDIAN
  b->word_[1].uint32_ <<= 8;
#else
  b->word_[1].uint32_ >>= 8;
#endif
  b->word_[1].uint08_[0] = temp1;

  // Shift of third row
  uint16_t temp2 = b->word_[2].uint16_[WORD_LASTIND_SHORT];
#if ENDIAN_UNKNOWN
  if(using_little_endian) b->word_[2].uint32_ <<= 16;
  else b->word_[2].uint32_ >>= 16;
#elif IS_LITTLE_ENDIAN
  b->word_[2].uint32_ <<= 16;
#else
  b->word_[2].uint32_ >>= 16;
#endif
  b->word_[2].uint16_[0] = temp2;

  // Shift of fourth row
  uint8_t temp3 = b->word_[3].uint08_[0];                                        // Three shift to the left is equivalent to one shift to the right
#if ENDIAN_UNKNOWN
  if(using_little_endian) b->word_[3].uint32_ >>= 8;
  else b->word_[3].uint32_ <<= 8;
#elif IS_LITTLE_ENDIAN
  b->word_[3].uint32_ >>= 8;
#else
  b->word_[3].uint32_ <<= 8;
#endif
  b->word_[3].uint08_[WORD_LASTIND] = temp3;
}

static void transposeBlock(const Block_t* source, Block_t* result){
  // Transposing and copying first column
  result->word_[0].uint08_[0] = source->word_[0].uint08_[0];
  result->word_[0].uint08_[1] = source->word_[1].uint08_[0];
  result->word_[0].uint08_[2] = source->word_[2].uint08_[0];
  result->word_[0].uint08_[3] = source->word_[3].uint08_[0];
  // Transposing and copying second column
  result->word_[1].uint08_[0] = source->word_[0].uint08_[1];
  result->word_[1].uint08_[1] = source->word_[1].uint08_[1];
  result->word_[1].uint08_[2] = source->word_[2].uint08_[1];
  result->word_[1].uint08_[3] = source->word_[3].uint08_[1];
  // Transposing and copying third column
  result->word_[2].uint08_[0] = source->word_[0].uint08_[2];
  result->word_[2].uint08_[1] = source->word_[1].uint08_[2];
  result->word_[2].uint08_[2] = source->word_[2].uint08_[2];
  result->word_[2].uint08_[3] = source->word_[3].uint08_[2];
  // Transposing and copying fourth column
  result->word_[3].uint08_[0] = source->word_[0].uint08_[3];
  result->word_[3].uint08_[1] = source->word_[1].uint08_[3];
  result->word_[3].uint08_[2] = source->word_[2].uint08_[3];
  result->word_[3].uint08_[3] = source->word_[3].uint08_[3];
}

static void MixColumns(Block_t* b) {                                              // -Mixes the data within each column of the state array.
  Block_t bT;
  transposeBlock(b,&bT);
  // First column
  b->uint08_[0] = dotProductWord(a.word_[0], bT.word_[0]);
  b->uint08_[4] = dotProductWord(a.word_[1], bT.word_[0]);
  b->uint08_[8] = dotProductWord(a.word_[2], bT.word_[0]);
  b->uint08_[12]= dotProductWord(a.word_[3], bT.word_[0]);
  // Second column
  b->uint08_[1] = dotProductWord(a.word_[0], bT.word_[1]);
  b->uint08_[5] = dotProductWord(a.word_[1], bT.word_[1]);
  b->uint08_[9] = dotProductWord(a.word_[2], bT.word_[1]);
  b->uint08_[13]= dotProductWord(a.word_[3], bT.word_[1]);
  // Third column
  b->uint08_[2] = dotProductWord(a.word_[0], bT.word_[2]);
  b->uint08_[6] = dotProductWord(a.word_[1], bT.word_[2]);
  b->uint08_[10]= dotProductWord(a.word_[2], bT.word_[2]);
  b->uint08_[14]= dotProductWord(a.word_[3], bT.word_[2]);
  // Fourth column
  b->uint08_[3] = dotProductWord(a.word_[0], bT.word_[3]);
  b->uint08_[7] = dotProductWord(a.word_[1], bT.word_[3]);
  b->uint08_[11]= dotProductWord(a.word_[2], bT.word_[3]);
  b->uint08_[15]= dotProductWord(a.word_[3], bT.word_[3]);
}

static void InvMixColumns(Block_t* b) {                                           // -Mixes the data within each column of the state array.
  Block_t bT;
  transposeBlock(b,&bT);
  // First column
  b->uint08_[0] = dotProductWord(aInv.word_[0], bT.word_[0]);
  b->uint08_[4] = dotProductWord(aInv.word_[1], bT.word_[0]);
  b->uint08_[8] = dotProductWord(aInv.word_[2], bT.word_[0]);
  b->uint08_[12]= dotProductWord(aInv.word_[3], bT.word_[0]);
  // Second column
  b->uint08_[1] = dotProductWord(aInv.word_[0], bT.word_[1]);
  b->uint08_[5] = dotProductWord(aInv.word_[1], bT.word_[1]);
  b->uint08_[9] = dotProductWord(aInv.word_[2], bT.word_[1]);
  b->uint08_[13]= dotProductWord(aInv.word_[3], bT.word_[1]);
  // Third column
  b->uint08_[2] = dotProductWord(aInv.word_[0], bT.word_[2]);
  b->uint08_[6] = dotProductWord(aInv.word_[1], bT.word_[2]);
  b->uint08_[10]= dotProductWord(aInv.word_[2], bT.word_[2]);
  b->uint08_[14]= dotProductWord(aInv.word_[3], bT.word_[2]);
  // Fourth column
  b->uint08_[3] = dotProductWord(aInv.word_[0], bT.word_[3]);
  b->uint08_[7] = dotProductWord(aInv.word_[1], bT.word_[3]);
  b->uint08_[11]= dotProductWord(aInv.word_[2], bT.word_[3]);
  b->uint08_[15]= dotProductWord(aInv.word_[3], bT.word_[3]);
}

enum ExceptionCode encryptBlock(const Block_t* input, const KeyExpansion_t* ke_p, Block_t* output, bool debug) {
  size_t i, j;
  // -Debugging purposes. Columns of the debugging table.
  Block_t* SOR;                                                                   // Start of round
  Block_t* ASB;                                                                   // After SubBytes
  Block_t* ASR;                                                                   // After ShiftRows
  Block_t *AMC;                                                                   // After MixColumns
  SOR = ASB = ASR = AMC = NULL;

  if(debug) {
    SOR = (Block_t*)malloc((ke_p->Nr+2)*sizeof(Block_t));
    AMC = (Block_t*)malloc((ke_p->Nr - 1)*sizeof(Block_t));
    ASB = (Block_t*)malloc(ke_p->Nr*sizeof(Block_t));
    ASR = (Block_t*)malloc(ke_p->Nr*sizeof(Block_t));
  }

  if(input == NULL) return NullInput;
  if(output== NULL) return NullOutput;
  if(input != output) copyBlock(input, output);

  if(debug) copyBlock(output,SOR);                                              // Equivalent to copyBlock(output,&SOR[0])

  if(ke_p == NULL) return NullKeyExpansion;
  AddRoundKey(output, ke_p->dataBlocks, 0);
  if(debug) copyBlock(output,SOR + 1);                                          // Equivalent to copyBlock(output,&SOR[1])
  for(i = 1; i < ke_p->Nr; i++) {
    SubBytes(output);
    if(debug) copyBlock(output, ASB + (i-1));
    ShiftRows(output);
    if(debug) copyBlock(output, ASR + (i-1));
    MixColumns(output);
    if(debug) copyBlock(output, AMC + (i-1));
    AddRoundKey(output, ke_p->dataBlocks, i);
    if(debug) copyBlock(output, SOR + (i+1));
  }
  SubBytes(output);
  if(debug) copyBlock(output, ASB + (i-1));
  ShiftRows(output);
  if(debug) copyBlock(output, ASR + (i-1));
  AddRoundKey(output, ke_p->dataBlocks, i);
  if(debug) copyBlock(output, SOR + (i-1));

  if(debug) {
    printf(
      "------------------------------------ Cipher. Nk = %d ------------------------------------\n"
      "----------------------------------------------------------------------------------------\n"
      " Round   |    Start of   |     After     |     After     |     After     |   Round key  \n"
      " Number  |     round     |    SubBytes   |   ShiftRows   |   MixColumns  |    value     \n"
      "         |               |               |               |               |              \n"
      "----------------------------------------------------------------------------------------\n",
      ke_p->Nk
    );

    for(i = 0; i < 4; i++) {
      if(i == 1) printf(" input  ");
      else printf("        ");
      printf(" | ");
      printWord(SOR[0].word_[i]);
      printf(" |               |               |               | ");
      printWord(ke_p->dataBlocks[0].word_[i]);
      printf("\n");
    }
    printf("\n");

    for(i = 1; i <= ke_p->Nr; i++) {
      for(j = 0; j < NB; j++) {
        if(j == 1) {
          printf("    ");
          if(i < 10) printf("%lu   ", i);
          else printf("%lu  ", i);
        }
        else printf("        ");
        printf(" | ");
        printWord(SOR[i].word_[j]);
        printf(" | ");
        printWord(ASB[i-1].word_[j]);
        printf(" | ");
        printWord(ASR[i-1].word_[j]);
        printf(" | ");
        if(i < ke_p->Nr) printWord(AMC[i-1].word_[j]);
        else printf("             ");
        printf(" | ");
        printWord(ke_p->dataBlocks[i].word_[j]);
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
      printWord(output->word_[i]);
      printf(" |               |               |               |               \n");
    }
    printf(
      "----------------------------------------------------------------------------------------\n"
    );
    debug = false;
  }
  if(SOR != NULL) { free(SOR); SOR=NULL; }
  if(ASB != NULL) { free(ASB); ASB=NULL; }
  if(ASR != NULL) { free(ASR); ASR=NULL; }
  if(AMC != NULL) { free(AMC); AMC=NULL; }

  return NoException;
}

enum ExceptionCode decryptBlock(const Block_t* input, const KeyExpansion_t* ke_p, Block_t* output, bool debug) {
  size_t i, j;
  // -Debugging purposes. Columns of the debugging table.
  Block_t* SOR;                                                                   // Start of round
  Block_t* AiSB;                                                                  // After SubBytes
  Block_t* AiSR;                                                                  // After ShiftRows
  Block_t* AARK;                                                                  // After MixColumns
  SOR = AiSB = AiSR = AARK = NULL;

  if(debug) {
    SOR = (Block_t*)malloc((ke_p->Nr+1)*sizeof(Block_t));
    AARK = (Block_t*)malloc(ke_p->Nr*sizeof(Block_t));
    AiSB = (Block_t*)malloc(ke_p->Nr*sizeof(Block_t));
    AiSR = (Block_t*)malloc(ke_p->Nr*sizeof(Block_t));
  }

  if(input == NULL) return NullInput;
  if(output== NULL) return NullOutput;
  if(input != output) copyBlock(input, output);

  if(debug) copyBlock(output,SOR + ke_p->Nr);                                   // Equivalent to copyBlock(output,&SOR[ke_p->Nr])

  if(ke_p == NULL) return NullKeyExpansion;
  AddRoundKey(output, ke_p->dataBlocks, ke_p->Nr);
  if(debug) copyBlock(output,SOR + ke_p->Nr-1);                                 // Equivalent to copyBlock(output,&SOR[ke_p->Nr])

  for(i = ke_p->Nr - 1; i > 0; i--) {
    InvShiftRows(output);
    if(debug) copyBlock(output, AiSR + i);
    InvSubBytes(output);
    if(debug) copyBlock(output, AiSB + i);
    AddRoundKey(output, ke_p->dataBlocks, i);
    if(debug) copyBlock(output, AARK + i);
    InvMixColumns(output);
    if(debug) copyBlock(output, SOR + (i-1));
  }
  InvShiftRows(output);
  if(debug) copyBlock(output, AiSR);
  InvSubBytes(output);
  if(debug) copyBlock(output, AiSB);
  AddRoundKey(output, ke_p->dataBlocks, 0);
  if(debug) copyBlock(output, AARK);

  if(debug) {
    printf(
      "---------------------------------- Decipher. Nk = %d ------------------------------------\n"
      "----------------------------------------------------------------------------------------\n"
      " Round   |    Start of   |     After     |     After     |     After     |   Round key  \n"
      " Number  |     round     |  InvShiftRows |  InvSubBytes  |  AddRoundKey  |    value     \n"
      "         |               |               |               |               |              \n"
      "----------------------------------------------------------------------------------------\n",
      ke_p->Nk
    );

    for(i = 0; i < NB; i++) {
      if(i == 1) printf(" input  ");
      else printf("        ");
      printf(" | ");
      printWord(SOR[ke_p->Nr].word_[i]);
      printf(" |               |               |               | ");
      printWord(ke_p->dataBlocks[0].word_[i]);
      printf("\n");
    }
    printf("\n");

    for(i = ke_p->Nr-1; i != (size_t)-1 ; i--) {
      for(j = 0; j < NB; j++) {
        if(j == 1) {
          printf("    ");
          if(i < 10) printf("%lu   ", i);
          else printf("%lu  ", i);
        }
        else printf("        ");
        printf(" | ");
        printWord(SOR[i].word_[j]);
        printf(" | ");
        printWord(AiSR[i].word_[j]);
        printf(" | ");
        printWord(AiSB[i].word_[j]);
        printf(" | ");
        printWord(AARK[i].word_[j]);
        printf(" | ");
        printWord(ke_p->dataBlocks[i].word_[j]);
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
      printWord(output->word_[i]);
      printf(" |               |               |               |               \n");
    }
    printf(
      "----------------------------------------------------------------------------------------\n"
    );
    debug = false;
  }
  if(SOR != NULL) { free(SOR); SOR=NULL; }
  if(AiSB != NULL) { free(AiSB); AiSB=NULL; }
  if(AiSR != NULL) { free(AiSR); AiSR=NULL; }
  if(AARK != NULL) { free(AARK); AARK=NULL; }

  return NoException;
}
