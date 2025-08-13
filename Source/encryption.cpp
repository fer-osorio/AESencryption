#include"AES.hpp"
#include<cstdint>
#include"OperationsGF256.hpp"

#define MAX_KEY_LENGTH_BYTES 32

/************************************* Default values for substitution boxes. This are the values showed in the standard ******************************************/


static const char a[4] 	  = {0x02, 0x03, 0x01, 0x01};				            // -For MixColumns.
static const char aInv[4] = {0x0E, 0x0B, 0x0D, 0x09};				            // -For InvMixColumns.

static const char Rcon[10][4] = {						                        // -Notice that the value of the left most char in polynomial form is 2^i.
	{0x01, 0x00, 0x00, 0x00},
  	{0x02, 0x00, 0x00, 0x00},
	{0x04, 0x00, 0x00, 0x00},
	{0x08, 0x00, 0x00, 0x00},
	{0x10, 0x00, 0x00, 0x00},
	{0x20, 0x00, 0x00, 0x00},
	{0x40, 0x00, 0x00, 0x00},
	{(char)0x80, 0x00, 0x00, 0x00},
	{0x1B, 0x00, 0x00, 0x00},
  	{0x36, 0x00, 0x00, 0x00}
};

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


void XORblocks(const char b1[AES_BLK_SZ],const char b2[AES_BLK_SZ], char r[AES_BLK_SZ]) {
    for(int i = 0; i < AES_BLK_SZ; i++) r[i] = b1[i] ^ b2[i];
}

void printState(const char state[AES_BLK_SZ]) {
	int i, j, temp;
	for(i = 0; i < 4; i++) {
		std::cout << '[';
		for(j = 0; j < 4; j++) {
		    temp = (uint8_t)0xFF & (uint8_t)state[(j << 2) + i];
			if(temp < 16) std::cout << '0';
			printf("%X", temp);
			if(j != 3) std::cout << ", ";
		}
		std::cout << "]\n";
	}
}

void CopyWord(const char source[4], char destination[4]) {
    for(int i = 0; i < 4; i++) destination[i] = source[i];
}

void CopyBlock(const char source[AES_BLK_SZ], char destination[AES_BLK_SZ]) {
    for(int i = 0; i < AES_BLK_SZ; i++) destination[i] = source[i];
}

void XORword(const char w1[4], const char w2[4], char resDest[4]) {
    for(int i = 0; i < 4; i++) resDest[i] = w1[i] ^ w2[i];
}

void RotWord(char word[4]) {
    char temp = word[0]; int i;
	for(i = 0; i < 3; i++) word[i] = word[i + 1];
	word[3] = temp;
}

void SubWord(char word[4]) {
    for(int i = 0; i < 4; i++) word[i] = (char)SBox[(uint8_t)word[i]];
}

void SubBytes(char state[AES_BLK_SZ]) {                            // -Applies a substitution table (S-box) to each char.
	for(int i = 0; i < AES_BLK_SZ; i++) state[i] = (char)SBox[(uint8_t)state[i]];
}

void ShiftRows(char state[AES_BLK_SZ]) {                           // -Shift rows of the state array by different offset.
	int i, j; char tmp[4];
	for(i = 1; i < 4; i++) {
		for(j = 0; j < 4; j++) tmp[j] = state[i + (j << 2)];
		for(j = 0; j < 4; j++) state[i + (j << 2)] = tmp[(j + i) & 3];
	}
}

void MixColumns(char state[AES_BLK_SZ]) {                          // -Mixes the data within each column of the state array.
    int i, I, j, k;
	char temp[4];
	for(i = 0; i < 4; i++) {
	    I = i << 2;                                                             // I = i * 4;
		for(k = 0; k < 4; k++) temp[k] = state[I + k];                          // Copying row.
		for(j = 0; j < 4; j++) {
			state[I + j] = (char)multiply[ (int)(uint8_t)a[(4 - j) & 3] ][ (int)(uint8_t)temp[0] ]; // -First state column element times matrix first column
			for(k = 1; k < 4; k++) {
				state[I + j] ^= (char)multiply[ (int)(uint8_t)a[(k - j + 4)&3] ][ (int)(uint8_t)temp[k] ];
			}
		}
	}
}

void AddRoundKey(char state[AES_BLK_SZ],const char keyExpansion[], size_t round) { // -Combines a round key with the state.
    round <<= 4;                                                                // -Each round uses 16 bytes and r <<= 4 == r *= 16.
	for(size_t i = 0; i < AES_BLK_SZ; i++) state[i] ^= keyExpansion[round + i];
}

void encryptBlock(char block[],const char keyExpansion[], size_t Nr) {
	int i, j;

	bool debug = false;                                                         // -True to show every encryption step.

	char *SOR, *ASB, *ASR, *AMC;                                                // -Debugging purposes.
	SOR = ASB = ASR = AMC = NULL;                                               // -Columns of the debugging table.

	if(debug) {                                                                 // (Nr + 2) * 16
        SOR = new char[(unsigned)(Nr + 2) << 4];
        AMC = new char[(unsigned)(Nr - 1) << 4];
        ASB = new char[(unsigned)Nr << 4];
        ASR = new char[(unsigned)Nr << 4];
	}

    if(debug) for(j = 0; j < AES_BLK_SZ; j++) SOR[j] = block[j];
	AddRoundKey(block, keyExpansion, 0);
	if(debug) for(j = 0; j < AES_BLK_SZ; j++) SOR[j + AES_BLK_SZ] = block[j];

	for(i = 1; i < Nr; i++) {
		SubBytes(block);
		if(debug) for(j = 0; j < AES_BLK_SZ; j++) ASB[((i - 1) << 4) + j] = block[j];

		ShiftRows(block);
		if(debug) for(j = 0; j < AES_BLK_SZ; j++) ASR[((i - 1) << 4) + j] = block[j];

		MixColumns(block);
		if(debug) for(j = 0; j < AES_BLK_SZ; j++) AMC[((i - 1) << 4) + j] = block[j];

		AddRoundKey(block, keyExpansion, i);
		if(debug) for(j = 0; j < AES_BLK_SZ; j++) SOR[((i + 1) << 4) + j] = block[j];
	}
	SubBytes(block);
	if(debug) for(j = 0; j < AES_BLK_SZ; j++) ASB[((i - 1) << 4) + j] = block[j];

	ShiftRows(block);
	if(debug) for(j = 0; j < AES_BLK_SZ; j++) ASR[((i - 1) << 4) + j] = block[j];

	AddRoundKey(block, keyExpansion, i);
	if(debug) for(j = 0; j < AES_BLK_SZ; j++) SOR[((i + 1) << 4) + j] = block[j];

	if(debug) {
	    auto printBlockRow = [] (const char blk[AES_BLK_SZ], int row) {
	        unsigned int temp = 0;
            std::cout << '[';
	        for(int i = 0; i < AES_BLK_SZ; i += 4) {
	            temp = (uint8_t)0xFF & (uint8_t)blk[row + i];
		        if(temp < 16) std::cout << '0';
		        printf("%X", temp);
		        if(i != 12) std::cout << ",";
	        }
	        std::cout << ']';
	    };

	    std::cout <<
	    "---------------------------------------- Cipher ----------------------------------------\n"
	    "----------------------------------------------------------------------------------------\n"
	    " Round   |    Start of   |     After     |     After     |     After     |   Round key  \n"
        " Number  |     round     |    SubBytes   |   ShiftRows   |   MixColumns  |    value     \n"
        "         |               |               |               |               |              \n"
        "----------------------------------------------------------------------------------------\n";

        for(i = 0; i < 4; i++) {
            i == 1 ? std::cout << " "  << "input"  << "  ": std::cout << "        " ;
            std::cout << " | ";
            printBlockRow(SOR, i);
            std::cout << " |               |               |               | ";
            printBlockRow(keyExpansion, i);
            std::cout << '\n';
        }
        std::cout << '\n';

        for(i = 1; i <= Nr; i++) {
            for(j = 0; j < 4; j++) {
                if(j == 1) {
                    std::cout << "    ";
                    if(i < 10) std::cout << i  << "   ";
                    else std::cout << i  << "  ";
                }
                else std::cout << "        " ;

                std::cout << " | ";
                printBlockRow(&SOR[(i << 4)], j);
                std::cout << " | ";
                printBlockRow(&ASB[((i - 1) << 4)], j);
                std::cout << " | ";
                printBlockRow(&ASR[((i - 1) << 4)], j);
                std::cout << " | ";
                if(i < Nr) printBlockRow(&AMC[((i - 1) << 4)], j);
                else std::cout << "             ";
                std::cout << " | ";
                printBlockRow(&keyExpansion[(i << 4)], j);
                std::cout << '\n';
            }
            std::cout <<
            "----------------------------------------------------------------------------------------\n";
        }
        for(i = 0; i < 4; i++) {
            i == 1 ? std::cout << " "  << "output"  << " ": std::cout << "        " ;
            std::cout << " | ";
            printBlockRow(block, i);
            std::cout << " |               |               |               |               \n";
        }
        std::cout <<
        "----------------------------------------------------------------------------------------\n";
	}
    if(SOR != NULL) delete[] SOR;
    if(ASB != NULL) delete[] ASB;
    if(ASR != NULL) delete[] ASR;
    if(AMC != NULL) delete[] AMC;
    debug = false;
}

void InvSubBytes(char state[AES_BLK_SZ]) {
    for(int i = 0; i < AES_BLK_SZ; i++) state[i] = (char)invSBox[(uint8_t)state[i]];
}

void InvShiftRows(char state[AES_BLK_SZ]) {
    int i, j; char temp[4];
	for(i = 1; i < 4; i++) {
		for(j = 0; j < 4; j++) temp[j] = state[i + (j << 2)];
		for(j = 0; j < 4; j++) state[(j << 2) + i] = temp[(j - i + 4) & 3];
	}
}

void InvMixColumns(char state[AES_BLK_SZ]) {
    int  i, j, k, I;
	char temp[4];
	for(i = 0; i < 4; i ++) {
	    I = i << 2;                                                             // -I = i * 4
		for(j = 0; j < 4; j++) temp[j] = state[I + j];
		for(j = 0; j < 4; j++) {
			state[I + j] = (char)multiply[ (int)(uint8_t)aInv[(4 - j) & 0x03] ][ (int)(uint8_t)temp[0] ];
			for(k = 1; k < 4; k++)
			    state[I + j] ^= (char)multiply[ (int)(uint8_t)aInv[(k - j + 4)&3] ][ (int)(uint8_t)temp[k] ];
		}
	}
}

void decryptBlock(char block[AES_BLK_SZ], const char keyExpansion[], size_t Nr) {
    int i = Nr;
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

using namespace AES;

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
}

