#include<stdio.h>
#include"SBox.h"
#include"GF256.h"
#include"cipher.h"

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

struct KeyExpansion{
  enum Nk_ Nk;
  size_t Nr;
  size_t wordsSize;
  size_t blockSize;
  Block* blocks;
};
static size_t getNr(enum Nk_ Nk){
  return Nk+6;
}
static size_t KeyExpansionLenWords(enum Nk_ Nk){
  return Nb*(getNr(Nk) + 1);
}
static size_t KeyExpansionLenBlocks(enum Nk_ Nk){
  return KeyExpansionLenWords(Nk) / Nb;
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
};

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

void blockFromBytes(const uint8_t source[], Block* output){
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

void printBlock(const Block* b, const char* rowHeaders[4]) {
  for(size_t i = 0; i < 4; i++) {
    if(rowHeaders != NULL) printf("%s",rowHeaders[i]);
      printWord(b->word_[i]);
      printf("\n");
    }
}

void XORblocks(const Block* b1,const Block* b2, Block* result) {
  result->uint64_[0] = b1->uint64_[0] ^ b2->uint64_[0];
  result->uint64_[1] = b1->uint64_[1] ^ b2->uint64_[1];
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

void transposeBlock(const Block* source, Block* result){
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

static void transposeUpdateBlock(Block* b){
  uint8_t buff;
  // Transposing and coping first column
  buff = b->word_[0].uint08_[1]; b->word_[0].uint08_[1] = b->word_[1].uint08_[0]; b->word_[1].uint08_[0] = buff;
  buff = b->word_[0].uint08_[2]; b->word_[0].uint08_[2] = b->word_[2].uint08_[0]; b->word_[2].uint08_[0] = buff;
  buff = b->word_[0].uint08_[3]; b->word_[0].uint08_[3] = b->word_[3].uint08_[0]; b->word_[3].uint08_[0] = buff;
  // Transposing and coping second column
  buff = b->word_[1].uint08_[2]; b->word_[1].uint08_[2] = b->word_[2].uint08_[1]; b->word_[2].uint08_[1] = buff;
  buff = b->word_[1].uint08_[3]; b->word_[1].uint08_[3] = b->word_[3].uint08_[1]; b->word_[3].uint08_[1] = buff;
  // Transposing and coping third column
  buff = b->word_[2].uint08_[3]; b->word_[2].uint08_[3] = b->word_[3].uint08_[2]; b->word_[3].uint08_[2] = buff;
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

static void KeyExpansionBuildWords(const Word key[], enum Nk_ Nk, Word outputKeyExpansion[], bool debug){
  Word tmp;
  const size_t keyExpLen = KeyExpansionLenWords(Nk);
  size_t i;

  for(i = 0; i < Nk; i++) outputKeyExpansion[i] = key[i];                             // -The first Nk words of the key expansion are the key itself.

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

/*
 * Builds a block using an array of four words.
 * Seeing words as vectors rows of a matrix, the resulting block is the transposed of this matrix
 * Considerations: Assuming that the pointer 'source' is pointing to a valid 4-words array
 * */
static void blockFromWords(const Word source[], Block* output){
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

void KeyExpansionBuild(const Word key[], enum Nk_ Nk, KeyExpansion_ptr outputKeyExpansion, bool debug){
  outputKeyExpansion->Nk = Nk;
  outputKeyExpansion->Nr = getNr(Nk);
  outputKeyExpansion->wordsSize = KeyExpansionLenWords(Nk);
  outputKeyExpansion->blockSize = KeyExpansionLenBlocks(Nk);
  Word* buffer = (Word*)malloc(outputKeyExpansion->wordsSize*sizeof(Word));
  KeyExpansionBuildWords(key, Nk, buffer, false);
  for(size_t i = 0, j = 0; i < outputKeyExpansion->wordsSize && j < outputKeyExpansion->blockSize; i += Nb, j++){
    blockFromWords(buffer + i, outputKeyExpansion->blocks + j);
  }
  free(buffer);
}

void encryptBlock(const Block* input, const KeyExpansion_ptr ke_p, Block* output, bool debug) {
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
  AddRoundKey(output, ke_p->blocks, 0);
  if(debug) copyBlock(output,SOR + 1);                                          // Equivalent to copyBlock(output,&SOR[1])

  for(i = 1; i < ke_p->Nr; i++) {
    SubBytes(output);
    if(debug) copyBlock(output, ASB + (i-1));

    ShiftRows(output);
    if(debug) copyBlock(output, ASR + (i-1));

    MixColumns(output);
    if(debug) copyBlock(output, AMC + (i-1));

    AddRoundKey(output, ke_p->blocks, i);
    if(debug) copyBlock(output, SOR + (i+1));
  }
  SubBytes(output);
  if(debug) copyBlock(output, ASB + (i-1));

  ShiftRows(output);
  if(debug) copyBlock(output, ASR + (i-1));

  AddRoundKey(output, ke_p->blocks, i);
  if(debug) copyBlock(output, SOR + (i-1));

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
      printf(" |               |               |               | ");
      printWord(ke_p->blocks[0].word_[i]);
      printf("\n");
    }
    printf("\n");

    for(i = 1; i <= ke_p->Nr; i++) {
      for(j = 0; j < Nb; j++) {
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
        printWord(ke_p->blocks[i].word_[j]);
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
  }
  if(SOR != NULL) { free(SOR); SOR=NULL; }
  if(ASB != NULL) { free(ASB); ASB=NULL; }
  if(ASR != NULL) { free(ASR); ASR=NULL; }
  if(AMC != NULL) { free(AMC); AMC=NULL; }
  debug = false;
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

void decryptBlock(const Block* input, const KeyExpansion_ptr ke_p, Block* output) {
  size_t i = ke_p->Nr;
  copyBlock (input, output);
  AddRoundKey(output, ke_p->blocks, i);
  for(i--; i > 0; i--) {
    InvShiftRows(output);
    InvSubBytes(output);
    AddRoundKey(output, ke_p->blocks, i);
    InvMixColumns(output);
  }
  InvShiftRows(output);
  InvSubBytes(output);
  AddRoundKey(output, ke_p->blocks, 0);
}
