#ifndef WORD_H
#define WORD_H

#include "../include/block.h"
#include <stdio.h>

static const Word_t Rcon[10] = {                                                  // Notice that the value of the left most byte in polynomial form is 2^i.
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

// Check for compiler-specific endianness macros
#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && defined(__ORDER_BIG_ENDIAN__)
    // GCC, Clang
    #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        #define IS_LITTLE_ENDIAN 1
        #define ENDIAN_UNKNOWN 0
    #elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        #define IS_LITTLE_ENDIAN 0
        #define ENDIAN_UNKNOWN 0
    #else
        #error "Unsupported endianness"
    #endif
#elif defined(_WIN32) || defined(_WIN64)
    // Windows is always little endian
    #define IS_LITTLE_ENDIAN 1
    #define ENDIAN_UNKNOWN 0
#elif defined(__LITTLE_ENDIAN__) || defined(__ARMEL__) || defined(__THUMBEL__) || \
      defined(__AARCH64EL__) || defined(_MIPSEL) || defined(__MIPSEL) || defined(__MIPSEL__)
    #define IS_LITTLE_ENDIAN 1
    #define ENDIAN_UNKNOWN 0
#elif defined(__BIG_ENDIAN__) || defined(__ARMEB__) || defined(__THUMBEB__) || \
      defined(__AARCH64EB__) || defined(_MIPSEB) || defined(__MIPSEB) || defined(__MIPSEB__)
    #define IS_LITTLE_ENDIAN 0
    #define ENDIAN_UNKNOWN 0
#else
    // Fallback: compile-time detection using union
    #define ENDIAN_UNKNOWN 1
#endif

static inline bool usingLittleEndian(){
  Word_t val = {.uint32_ = 1};
  return val.uint08_[0] == 1;
}
static int using_little_endian = -1;

static inline void printWord(Word_t w) {
  uint32_t WL_1 = WORD_SIZE-1, i;
  printf("[");
  for(i = 0; i < WL_1; i++) printf("%.2X,", (uint32_t)w.uint08_[i]);
  printf("%.2X]", (uint32_t)w.uint08_[i]);
}

static inline void copyWord(const Word_t* orgin, Word_t* dest){
  dest->uint32_ = orgin->uint32_;
}

static inline void RotWord(Word_t* word) {
  uint8_t temp = word->uint08_[0];
#if ENDIAN_UNKNOWN
  if(using_little_endian == -1) using_little_endian = usingLittleEndian();
  if(using_little_endian) word->uint32_ >>= 8;
  else word->uint32_ <<= 8;
#elif IS_LITTLE_ENDIAN
  word->uint32_ >>= 8;
#else
  word->uint32_ <<= 8;
#endif
  word->uint08_[WORD_LASTIND] = temp;
}

#ifdef SBOX_H
static inline void SubWord(Word_t* w) {
  w->uint08_[0] = SBox[w->uint08_[0]];
  w->uint08_[1] = SBox[w->uint08_[1]];
  w->uint08_[2] = SBox[w->uint08_[2]];
  w->uint08_[3] = SBox[w->uint08_[3]];
}

static inline void InvSubWord(Word_t* w) {
  w->uint08_[0] = invSBox[w->uint08_[0]];
  w->uint08_[1] = invSBox[w->uint08_[1]];
  w->uint08_[2] = invSBox[w->uint08_[2]];
  w->uint08_[3] = invSBox[w->uint08_[3]];
}
#endif

static inline void XORword(const Word_t b1, const Word_t b2, Word_t* result) {
  result->uint32_ = b1.uint32_ ^ b2.uint32_;
}

#ifdef GF256_H
/*
 * Classical dot product with vectors of dimension four with coefficients in GF(256)
 * */
static inline uint8_t dotProductWord(const Word_t w1, const Word_t w2){
  return  multiply[w1.uint08_[0]][w2.uint08_[0]] ^
          multiply[w1.uint08_[1]][w2.uint08_[1]] ^
          multiply[w1.uint08_[2]][w2.uint08_[2]] ^
          multiply[w1.uint08_[3]][w2.uint08_[3]];
}
#endif

#endif
