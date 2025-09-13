#include"../include/constants.h"

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
  return UnknownNr;
}

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
  return UnknowKeyExpansionLengthBytes;
}

enum KeyExpansionLengthWords_t getKeyExpansionLengthWordsfromNk(enum Nk_t Nk){
  switch(Nk){
    case Nk128:
      return KeyExpansionLengthWords128;
      break;
    case Nk192:
      return KeyExpansionLengthWords192;
      break;
    case Nk256:
      return KeyExpansionLengthWords256;
      break;
      break;
    case UnknownNk:
      return UnknowKeyExpansionLengthWords;
      break;
  }
  return UnknowKeyExpansionLengthWords;
}

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
  return UnknownNk;
}
