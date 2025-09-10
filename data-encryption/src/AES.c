#include"../include/constants.h"
#include"../include/AES.h"
#include<stdio.h>
#include"SBox.h"
#include"GF256.h"

#define WORD_SIZE_SHORTS 2
#define WORD_LASTIND 3                                                          // -Last index of a word
#define WORD_LASTIND_SHORT 1                                                    // -Last index of a word using short's
typedef union Word_ {
  uint8_t  uint08_[WORD_SIZE];
  uint16_t uint16_[WORD_SIZE_SHORTS];
  uint32_t uint32_;
} Word ;

#define BLOCK_SIZE_INT64 2
typedef union Block_{
    uint8_t  uint08_[BLOCK_SIZE];
    Word     word_[NB];
    uint64_t uint64_[BLOCK_SIZE_INT64];
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

struct KeyExpansion_{
  enum Nk_t Nk;
  size_t Nr;
  size_t wordsSize;
  size_t blockSize;
  Block* dataBlocks;
};
static size_t getNr(enum Nk_t Nk){
  return Nk+6;
}
static size_t KeyExpansionLenWords(enum Nk_t Nk){
  return NB*(getNr(Nk) + 1);
}
static size_t KeyExpansionLenBlocks(enum Nk_t Nk){
  return KeyExpansionLenWords(Nk) / NB;
}

static bool usingLittleEndian(){
  Word val = {.uint32_ = 1};                                                                // Represents 0x00000001 in hexadecimal
  return val.uint08_[0] == 1;                                                  // Cast the address of the integer to a uint8_t pointer to access individual bytes
}

static void printWord(Word w) {
  uint32_t WL_1 = WORD_SIZE-1, i;
  printf("[");
  for(i = 0; i < WL_1; i++) printf("%.2X,", (uint32_t)w.uint08_[i]);
  printf("%.2X]", (uint32_t)w.uint08_[i]);
}

static void copyWord(const Word* orgin, Word* dest){
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

/*
 * Classical dot product with vectors of dimension four with coefficients in GF(256)
 * */
static uint8_t dotProductWord(const Word w1, const Word w2){                  // Classical dot product with vectors of dimension four with coefficients in
  return  multiply[w1.uint08_[0]][w2.uint08_[0]] ^                          // GF(256)
          multiply[w1.uint08_[1]][w2.uint08_[1]] ^
          multiply[w1.uint08_[2]][w2.uint08_[2]] ^
          multiply[w1.uint08_[3]][w2.uint08_[3]];
}

static void BlockWriteFromBytes(const uint8_t source[], Block* output){
  // First column
  output->uint08_[0] = source[0];
  output->uint08_[4] = source[1];
  output->uint08_[8] = source[2];
  output->uint08_[12]= source[3];
  // Second column
  output->uint08_[1] = source[4];
  output->uint08_[5] = source[5];
  output->uint08_[9] = source[6];
  output->uint08_[13]= source[7];
  // Third column
  output->uint08_[2] = source[8];
  output->uint08_[6] = source[9];
  output->uint08_[10]= source[10];
  output->uint08_[14]= source[11];
  // Third column
  output->uint08_[3] = source[12];
  output->uint08_[7] = source[13];
  output->uint08_[11]= source[14];
  output->uint08_[15]= source[15];
}

Block_ptr BlockMemoryAllocationFromBytes(const uint8_t source[]){
  Block_ptr output = (Block*)malloc(sizeof(Block));
  if(output == NULL) return NULL;
  BlockWriteFromBytes(source, output);
  return output;
}

void BlockDelete(Block** blk_pp){
  Block* blk_p = *blk_pp;
  if(blk_p != NULL) free(blk_p);
  *blk_pp = NULL;
}

void bytesFromBlock(const Block* source, uint8_t output[]){
  // First column
  output[0] = source->uint08_[0];
  output[4] = source->uint08_[1];
  output[8] = source->uint08_[2];
  output[12]= source->uint08_[3];
  // Second column
  output[1] = source->uint08_[4];
  output[5] = source->uint08_[5];
  output[9] = source->uint08_[6];
  output[13]= source->uint08_[7];
  // Third column
  output[2] = source->uint08_[8];
  output[6] = source->uint08_[9];
  output[10]= source->uint08_[10];
  output[14]= source->uint08_[11];
  // Third column
  output[3] = source->uint08_[12];
  output[7] = source->uint08_[13];
  output[11]= source->uint08_[14];
  output[15]= source->uint08_[15];
}

Block_ptr BlockMemoryAllocationRandom(unsigned int seed){
  Block_ptr output = (Block*)malloc(sizeof(Block));
  if(output == NULL) return NULL;
  srand(seed);
  for(size_t i = 0; i < NB; i++) output->word_[i].uint32_ = rand();
  return output;
}

void printBlock(const Block* b, const char* rowHeaders[4]) {
  for(size_t i = 0; i < 4; i++) {
    if(rowHeaders != NULL) printf("%s",rowHeaders[i]);
      printWord(b->word_[i]);
      printf("\n");
    }
}

static void XORblocks(const Block* b1,const Block* b2, Block* result) {
  result->uint64_[0] = b1->uint64_[0] ^ b2->uint64_[0];
  result->uint64_[1] = b1->uint64_[1] ^ b2->uint64_[1];
}

void BlockXORequalBytes(Block* input, const uint8_t byteBlock[]){
  input->uint08_[0] ^= byteBlock[0];
  input->uint08_[1] ^= byteBlock[4];
  input->uint08_[2] ^= byteBlock[8];
  input->uint08_[3] ^= byteBlock[12];
  input->uint08_[4] ^= byteBlock[1];
  input->uint08_[5] ^= byteBlock[5];
  input->uint08_[6] ^= byteBlock[9];
  input->uint08_[7] ^= byteBlock[13];
  input->uint08_[8] ^= byteBlock[2];
  input->uint08_[9] ^= byteBlock[6];
  input->uint08_[10] ^= byteBlock[10];
  input->uint08_[11] ^= byteBlock[14];
  input->uint08_[12] ^= byteBlock[3];
  input->uint08_[13] ^= byteBlock[7];
  input->uint08_[14] ^= byteBlock[11];
  input->uint08_[15] ^= byteBlock[15];
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
  bool isLittleEndian = usingLittleEndian();                                    // isLittleEndian will determine the direction of the shift
  // Shift of second row
  uint8_t temp1 = b->word_[1].uint08_[0];                                       // As a byte array, the rotation must be performed to the left, but since integer
  if(isLittleEndian) b->word_[1].uint32_ >>= 8;                                 // types have endianess, the bit rotation must be perform according to it
  else b->word_[1].uint32_ <<= 8;
  b->word_[1].uint08_[WORD_LASTIND] = temp1;

  // Shift of third row
  uint16_t temp2 = b->word_[2].uint16_[0];
  if(isLittleEndian) b->word_[2].uint32_ >>= 16;
  else b->word_[2].uint32_ <<= 16;
  b->word_[2].uint16_[WORD_LASTIND_SHORT] = temp2;

  // Shift of fourth row
  uint8_t temp3 = b->word_[3].uint08_[WORD_LASTIND];                            // Three shift to the left is equivalent to one shift to the right
  if(isLittleEndian) b->word_[3].uint32_ <<= 8;
  else b->word_[3].uint32_ >>= 8;
  b->word_[3].uint08_[0] = temp3;
}

static void transposeBlock(const Block* source, Block* result){
  // Transposing and coping first column
  result->word_[0].uint08_[0] = source->word_[0].uint08_[0];
  result->word_[0].uint08_[1] = source->word_[1].uint08_[0];
  result->word_[0].uint08_[2] = source->word_[2].uint08_[0];
  result->word_[0].uint08_[3] = source->word_[3].uint08_[0];
  // Transposing and coping second column
  result->word_[1].uint08_[0] = source->word_[0].uint08_[1];
  result->word_[1].uint08_[1] = source->word_[1].uint08_[1];
  result->word_[1].uint08_[2] = source->word_[2].uint08_[1];
  result->word_[1].uint08_[3] = source->word_[3].uint08_[1];
  // Transposing and coping third column
  result->word_[2].uint08_[0] = source->word_[0].uint08_[2];
  result->word_[2].uint08_[1] = source->word_[1].uint08_[2];
  result->word_[2].uint08_[2] = source->word_[2].uint08_[2];
  result->word_[2].uint08_[3] = source->word_[3].uint08_[2];
  // Transposing and coping fourth column
  result->word_[3].uint08_[0] = source->word_[0].uint08_[3];
  result->word_[3].uint08_[1] = source->word_[1].uint08_[3];
  result->word_[3].uint08_[2] = source->word_[2].uint08_[3];
  result->word_[3].uint08_[3] = source->word_[3].uint08_[3];
}

static void MixColumns(Block* b) {                                              // -Mixes the data within each column of the state array.
  Block bT;
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
  // Third column
  b->uint08_[3] = dotProductWord(a.word_[0], bT.word_[3]);
  b->uint08_[7] = dotProductWord(a.word_[1], bT.word_[3]);
  b->uint08_[11]= dotProductWord(a.word_[2], bT.word_[3]);
  b->uint08_[15]= dotProductWord(a.word_[3], bT.word_[3]);
}

static void AddRoundKey(Block* b, const Block keyExpansion[], size_t round) {   // -Combines a round key with the state.
  XORblocks(b,keyExpansion+round,b);
}

static void KeyExpansionBuildWords(const uint8_t* key, enum Nk_t Nk, Word outputKeyExpansion[], bool debug){
  Word tmp;
  const size_t keyExpLen = KeyExpansionLenWords(Nk);
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

  for(i = Nk; i < keyExpLen; i++) {
    copyWord(&outputKeyExpansion[i - 1], &tmp);                                       // -Guarding against modify things that we don't want to modify.
    if(debug) {
      printf(" %lu",i);
      if(i < 10) printf("  | ");
      else printf(" | ");
      printWord(tmp);
    }
    if((i % Nk) == 0) {                                                         // -i is a multiple of Nk, witch value is 8
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

static KeyExpansion_ptr KeyExpansionMemoryAllocation(enum Nk_t Nk){
  KeyExpansion_ptr output = (KeyExpansion*)malloc(sizeof(KeyExpansion));
  if(output == NULL) return NULL;
  // -Building KeyExpansion object
  output->Nk = Nk;
  output->Nr = getNr(Nk);
  output->wordsSize = KeyExpansionLenWords(Nk);
  output->blockSize = KeyExpansionLenBlocks(Nk);
  output->dataBlocks = (Block*)malloc(output->blockSize*sizeof (Block));
  if(output->dataBlocks == NULL) return NULL;
  return output;
}

static enum Nk_t keylenbitsToNk(uint32_t keylenbits){                                        // Casting from unsigned integer to Nk value
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
 * Seeing words as vectors rows of a matrix, the resulting block is the transposed of this matrix
 * Considerations: Assuming that the pointer 'source' is pointing to a valid 4-words array
 * */
static void BlockFromWords(const Word source[], Block* output){
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

KeyExpansion_ptr KeyExpansionMemoryAllocationBuild(const uint8_t* key, size_t keylenbits, bool debug){
  enum Nk_t Nk = keylenbitsToNk(keylenbits);
  if(Nk == UnknownNk) {
    //printf("KeyExpansionMemoryAllocationBuild: Nk == Unknown\n");
    //printf("KeyExpansionMemoryAllocationBuild: nk == %lu\n", nk);
    return NULL;
  }

  KeyExpansion_ptr output = KeyExpansionMemoryAllocation(Nk);
  if(output == NULL) return NULL;

  Word* buffer = (Word*)malloc(output->wordsSize*sizeof(Word));
  if(buffer == NULL) return NULL;

  // Writing key expansion on array of words
  KeyExpansionBuildWords(key, Nk, buffer, debug);
  // Writting key expansion on the array of Blocks 'inside' KeyExpansion object.
  for(size_t i = 0, j = 0; i < output->wordsSize && j < output->blockSize; i += NB, j++){
    BlockFromWords(buffer + i, output->dataBlocks + j);
  }
  free(buffer);
  return output;
}

void KeyExpansionDelete(KeyExpansion** ke_pp){
  KeyExpansion* ke_p = *ke_pp;
  if(ke_p != NULL){
    if(ke_p->dataBlocks != NULL) {
      free(ke_p->dataBlocks);
      ke_p->dataBlocks = NULL;                                                      // Signaling that the memory is has been freed.
    }
    free(ke_p);
    *ke_pp = NULL;                                                              // Signaling that the memory is has been freed.
  }
}

void KeyExpansionWriteBytes(const KeyExpansion* source, uint8_t* dest){
  for(size_t i = 0, j = 0; i < source->blockSize; i++, j += BLOCK_SIZE){
    bytesFromBlock(source->dataBlocks + i, dest + j);
  }
}

KeyExpansion_ptr KeyExpansionFromBytes(const uint8_t source[], size_t keylenbits){
  enum Nk_t Nk = keylenbitsToNk(keylenbits);
  if(Nk == UnknownNk) return NULL;
  KeyExpansion_ptr output = KeyExpansionMemoryAllocation(Nk);
  if(output == NULL) return NULL;
  for(size_t i = 0, j = 0; i < output->blockSize; i++, j += BLOCK_SIZE){
    BlockWriteFromBytes(source + j,output->dataBlocks + i);
  }
  return output;
}

const uint8_t* KeyExpansionReturnBytePointerToData(const KeyExpansion*const ke_p){
  return (uint8_t*)ke_p->dataBlocks;
}

void encryptBlock(const Block* input, const KeyExpansion* ke_p, Block* output, bool debug) {
  size_t i, j;
  // -Debugging purposes. Columns of the debugging table.
  Block* SOR;                                                                   // Start of round
  Block* ASB;                                                                   // After SubBytes
  Block* ASR;                                                                   // After ShiftRows
  Block *AMC;                                                                   // After MixColumns
  SOR = ASB = ASR = AMC = NULL;

  if(debug) {
    SOR = (Block*)malloc((ke_p->Nr+2)*sizeof(Block));
    AMC = (Block*)malloc((ke_p->Nr - 1)*sizeof(Block));
    ASB = (Block*)malloc(ke_p->Nr*sizeof(Block));
    ASR = (Block*)malloc(ke_p->Nr*sizeof(Block));
  }

  if(input != output) copyBlock(input, output);

  if(debug) copyBlock(output,SOR);                                              // Equivalent to copyBlock(output,&SOR[0])
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
}

static void InvShiftRows(Block* b) {                                            // -Shift rows of the state array by different offset.
  bool isLittleEndian = usingLittleEndian();                                    // isLittleEndian will determine the direction of the shift

  // Shift of second row
  uint8_t temp1 = b->word_[1].uint08_[WORD_LASTIND];                                          // As a byte array, the rotation must be performed to the left, but since integer
  if(isLittleEndian) b->word_[1].uint32_ <<= 8;                                 // types have endianess, the bit rotation must be perform according to it
  else b->word_[1].uint32_ >>= 8;
  b->word_[1].uint08_[0] = temp1;

  // Shift of third row
  uint16_t temp2 = b->word_[2].uint16_[WORD_LASTIND_SHORT];
  if(isLittleEndian) b->word_[2].uint32_ <<= 16;
  else b->word_[2].uint32_ >>= 16;
  b->word_[2].uint16_[0] = temp2;

  // Shift of fourth row
  uint8_t temp3 = b->word_[3].uint08_[0];                                       // Three shift to the left is equivalent to one shift to the right
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

static void InvSubBytes(Block* b) {                                             // -Applies a substitution table (S-box) to each uint8_t.
    InvSubWord(&b->word_[0]);
    InvSubWord(&b->word_[1]);
    InvSubWord(&b->word_[2]);
    InvSubWord(&b->word_[3]);
}

static void InvMixColumns(Block* b) {                                           // -Mixes the data within each column of the state array.
  Block bT;
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
  // Third column
  b->uint08_[3] = dotProductWord(aInv.word_[0], bT.word_[3]);
  b->uint08_[7] = dotProductWord(aInv.word_[1], bT.word_[3]);
  b->uint08_[11]= dotProductWord(aInv.word_[2], bT.word_[3]);
  b->uint08_[15]= dotProductWord(aInv.word_[3], bT.word_[3]);
}

void decryptBlock(const Block* input, const KeyExpansion* ke_p, Block* output, bool debug) {
  size_t i, j;
  // -Debugging purposes. Columns of the debugging table.
  Block* SOR;                                                                   // Start of round
  Block* AiSB;                                                                  // After SubBytes
  Block* AiSR;                                                                  // After ShiftRows
  Block* AARK;                                                                  // After MixColumns
  SOR = AiSB = AiSR = AARK = NULL;

  if(debug) {
    SOR = (Block*)malloc((ke_p->Nr+1)*sizeof(Block));
    AARK = (Block*)malloc(ke_p->Nr*sizeof(Block));
    AiSB = (Block*)malloc(ke_p->Nr*sizeof(Block));
    AiSR = (Block*)malloc(ke_p->Nr*sizeof(Block));
  }

  if(input != output) copyBlock(input, output);

  if(debug) copyBlock(output,SOR + ke_p->Nr);                                   // Equivalent to copyBlock(output,&SOR[ke_p->Nr])
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
}
