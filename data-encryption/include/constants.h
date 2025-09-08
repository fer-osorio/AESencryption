// Constants defined using NIST standard or derived from it.
#ifndef _CONSTANTS_
#define _CONSTANTS_

#define WORD_SIZE 4
#define BLOCK_SIZE 16

#define NB 4;

#define NK128 4
#define NK192 6
#define NK256 8
enum Nk_{Unknown, Nk128 = NK128, Nk192 = NK192, Nk256 = NK256};

#define NR128 10;
#define NR192 12;
#define NR256 14;

#define KEY_EXPANSION_LENGTH_128 44;
#define KEY_EXPANSION_LENGTH_192 52;
#define KEY_EXPANSION_LENGTH_256 60;

#endif
