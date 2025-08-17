#include<stdio.h>
#include"cipher.h"

static size_t getNr(Nk nk){
  return nk+6;
}
static size_t keyExpansionLenght(Nk nk){
  return Nb*(getNr(nk) + 1);
}

static bool usingLittleEndian(){
  Word val = {.uint32_ = 1};                                                                // Represents 0x00000001 in hexadecimal
  return val.uint08_[0] == 1;                                                  // Cast the address of the integer to a uint8_t pointer to access individual bytes
}

static void printWord(Word w) {
  uint32_t WL_1 = WORD_LEN-1, i;
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

static void printBlock(const Block* b, const char* rowHeaders[4]) {
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

static void build_KeyExpansion(const Word key[], Nk nk, Word keyExpansion[], bool debug){
  Word tmp;
  const size_t keyExpLen = keyExpansionLenght(nk);
  size_t i;

  for(i = 0; i < nk; i++) keyExpansion[i] = key[i];                             // -The first Nk words of the key expansion are the key itself.

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

  for(i = nk; i < keyExpLen; i++) {
    copyWord(&keyExpansion[i - 1], &tmp);                                       // -Guarding against modify things that we don't want to modify.
    if(debug) {
      printf(" %lu",i);
      if(i < 10) printf("  | ");
      else printf(" | ");
      printWord(tmp);
    }
    if((i % nk) == 0) {                                                         // -i is a multiple of Nk, witch value is 8
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
        printWord(Rcon[i/nk - 1]);
      }
      XORword(tmp, Rcon[i/nk -1], &tmp);
      if(debug) {
        printf(" | ");
        printWord(tmp);
      }
    } else {
      if(nk > 6 && (i % nk) == 4) {
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
      printWord(keyExpansion[i - nk]);
    }
    XORword(keyExpansion[i - nk], tmp, &keyExpansion[i]);
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
  for(i = 0; i < keyExpLen; i+=Nb) transposeUpdateBlock((Block*)&keyExpansion[i]);
}

void encryptBlock(const Block* input, const Block keyExpansion[], Nk nk, Block* output, bool debug) {
  size_t i, j;
  size_t Nr = getNr(nk);
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

  copyBlock(input, output);

  if(debug) copyBlock(output,SOR);                                              // Equivalent to copyBlock(output,&SOR[0])
  AddRoundKey(output, keyExpansion, 0);
  if(debug) copyBlock(output,SOR + 1);                                          // Equivalent to copyBlock(output,&SOR[1])

  for(i = 1; i < Nr; i++) {
    SubBytes(output);
    if(debug) copyBlock(output, ASB + (i-1));
    //if(debug) for(j = 0; j < BLOCK_LEN; j++) ASB[((i - 1) << 4) + j] = output->uint08_[j];

    ShiftRows(output);
    if(debug) copyBlock(output, ASR + (i-1));
    //if(debug) for(j = 0; j < BLOCK_LEN; j++) ASR[((i - 1) << 4) + j] = output->uint08_[j];

    MixColumns(output);
    if(debug) copyBlock(output, AMC + (i-1));
    //if(debug) for(j = 0; j < BLOCK_LEN; j++) AMC[((i - 1) << 4) + j] = output->uint08_[j];

    AddRoundKey(output, keyExpansion, i);
    if(debug) copyBlock(output, SOR + (i+1));
    //if(debug) for(j = 0; j < BLOCK_LEN; j++) SOR[((i + 1) << 4) + j] = output->uint08_[j];
  }
  SubBytes(output);
  if(debug) copyBlock(output, ASB + (i-1));
  //if(debug) for(j = 0; j < BLOCK_LEN; j++) ASB[((i - 1) << 4) + j] = output->uint08_[j];

  ShiftRows(output);
  if(debug) copyBlock(output, ASR + (i-1));
  //if(debug) for(j = 0; j < BLOCK_LEN; j++) ASR[((i - 1) << 4) + j] = output->uint08_[j];

  AddRoundKey(output, keyExpansion, i);
  if(debug) copyBlock(output, SOR + (i-1));
  //if(debug) for(j = 0; j < BLOCK_LEN; j++) SOR[((i + 1) << 4) + j] = output->uint08_[j];

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
          if(i < 10) printf("%lu   ", i);
          else printf("%lu  ", i);
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

void decryptBlock(Block* input, const Block keyExpansion[], Nk nk, Block* output) {
  size_t Nr = getNr (nk);
  size_t i = Nr;
  copyBlock (input, output);
  AddRoundKey(output, keyExpansion, i);
  for(i--; i > 0; i--) {
    InvShiftRows(output);
    InvSubBytes(output);
    AddRoundKey(output, keyExpansion, i);
    InvMixColumns(output);
  }
  InvShiftRows(output);
  InvSubBytes(output);
  AddRoundKey(output,keyExpansion, 0);
}

#define Nk128_KEYEXPLEN 44    // Length in words of the Key Expansion of a 128 bits key; Nb*(Nr+1), Nr = Nk+6

int main(int argc, char* argv[]){
  const Word key128[Nk128] = {{{0x2b,0x7e,0x15,0x16}},{{0x28,0xae,0xd2,0xa6}},{{0xab,0xf7,0x15,0x88}},{{0x09,0xcf,0x4f,0x3c}}};
  Block plaintext128 = {{0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34}};
  Block ciphertext128 = {0}, deciphertext = {0};
  Word keyExpansion128[Nk128_KEYEXPLEN] = {0};
  build_KeyExpansion(key128, Nk128, keyExpansion128, true);
  printf("\n");
  transposeUpdateBlock(&plaintext128);
  const char* plaintextRowHeaders[4] = {"      ","Plain ","Text  ","      "};
  printBlock(&plaintext128, plaintextRowHeaders);
  encryptBlock(&plaintext128, (Block*)keyExpansion128, Nk128, &ciphertext128, true);
  decryptBlock(&ciphertext128, (Block*)keyExpansion128, Nk128, &deciphertext);
  printf("\n");
  const char* rowHeaders[4] = {"           ","Deciphered ","Text       ","           "};
  transposeUpdateBlock(&deciphertext);
  printBlock(&deciphertext, rowHeaders);
  return EXIT_SUCCESS;
}
