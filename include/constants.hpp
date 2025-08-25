#ifndef _CONSTANTS_
#define _CONSTANTS_

namespace AESconstants{
constexpr unsigned int BLOCK_SIZE = 16;

constexpr unsigned int Nb = 4;

constexpr unsigned int Nk128 = 4;
constexpr unsigned int Nk192 = 6;
constexpr unsigned int Nk256 = 8;

constexpr unsigned int Nr128 = 10;
constexpr unsigned int Nr192 = 12;
constexpr unsigned int Nr256 = 14;

constexpr unsigned int keyExpansionLength128 = 44;
constexpr unsigned int keyExpansionLength192 = 52;
constexpr unsigned int keyExpansionLength256 = 60;
};

#endif