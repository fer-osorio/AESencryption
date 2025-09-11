// Constants defined using NIST standard or derived from it.
#ifndef _CONSTANTS_
#define _CONSTANTS_

#define WORD_SIZE 4
#define BLOCK_SIZE 16

#define KEY_LENGTH_BITS_128 128
#define KEY_LENGTH_BITS_192 192
#define KEY_LENGTH_BITS_256 256
enum KeylenBits_t{
  UnknownKeylenBits, Keylenbits128 = KEY_LENGTH_BITS_128, Keylenbits192 = KEY_LENGTH_BITS_192, Keylenbits256 = KEY_LENGTH_BITS_256
};

#define NB 4

#define NK128 4
#define NK192 6
#define NK256 8
enum Nk_t{
  UnknownNk, Nk128 = NK128, Nk192 = NK192, Nk256 = NK256
};
enum Nk_t getNkfromKeylenBits(enum KeylenBits_t klb){
  switch(klb){
    case Keylenbits128:
      return Nk128;
      break;
    case Keylenbits192:
      return Nk192;
      break;
    case Keylenbits256:
      return Nk256;
      break;
    case UnknownKeylenBits:
      return UnknownNk;
      break;
  }
}

#define NR128 10
#define NR192 12
#define NR256 14
enum Nr_t{
  UnknownNr, Nr128 = NR128, Nr192 = NR192, Nr256 = NR256
};
enum Nr_t getNrfromNk(enum Nk_t Nk){
  switch(Nk){
    case Nk128:
      return Nr128;
      break;
    case Nk192:
      return Nr192;
      break;
    case Nk256:
      return Nr256;
      break;
    case UnknownNk:
      return UnknownNr;
      break;
  }
}

#define KEY_EXPANSION_LENGTH_128_BYTES 176
#define KEY_EXPANSION_LENGTH_192_BYTES 208
#define KEY_EXPANSION_LENGTH_256_BYTES 240
enum KeyExpansionLengthBytes_t{
  UnknowKeyExpansionLengthBytes,
  KeyExpansionLengthBytes128 = KEY_EXPANSION_LENGTH_128_BYTES,
  KeyExpansionLengthBytes192 = KEY_EXPANSION_LENGTH_192_BYTES,
  KeyExpansionLengthBytes256 = KEY_EXPANSION_LENGTH_256_BYTES
};
enum KeyExpansionLengthBytes_t getKeyExpansionLengthBytesfromKeylenBits(enum KeylenBits_t klb){
  switch(klb){
    case Keylenbits128:
      return KeyExpansionLengthBytes128;
      break;
    case Keylenbits192:
      return KeyExpansionLengthBytes192;
      break;
    case Keylenbits256:
      return KeyExpansionLengthBytes256;
      break;
      break;
    case UnknownKeylenBits:
      return UnknowKeyExpansionLengthBytes;
      break;
  }
}

#define KEY_EXPANSION_LENGTH_128_WORDS 44
#define KEY_EXPANSION_LENGTH_192_WORDS 52
#define KEY_EXPANSION_LENGTH_256_WORDS 60
enum KeyExpansionLengthWords_t{
  UnknowKeyExpansionLengthWords,
  KeyExpansionLengthWords128 = KEY_EXPANSION_LENGTH_128_BYTES,
  KeyExpansionLengthWords192 = KEY_EXPANSION_LENGTH_192_BYTES,
  KeyExpansionLengthWords256 = KEY_EXPANSION_LENGTH_256_BYTES
};
enum KeyExpansionLengthWords_t getKeyExpansionLengthWordsfromKeylenBits(enum KeylenBits_t klb){
  switch(klb){
    case Keylenbits128:
      return KeyExpansionLengthWords128;
      break;
    case Keylenbits192:
      return KeyExpansionLengthWords192;
      break;
    case Keylenbits256:
      return KeyExpansionLengthWords256;
      break;
      break;
    case UnknownKeylenBits:
      return UnknowKeyExpansionLengthWords;
      break;
  }
}

#endif
