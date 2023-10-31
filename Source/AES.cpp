#include<iostream>
#include<fstream>
#include"AES.hpp"
#include"OperationsGF256.hpp"

AES::AES(const char* const _key, AESkey::Length len)
: key(_key, len, AESkey::ECB), Nk(len >> 5), Nr(Nk+6), keyExpLen((Nr+1)<<4) {
    this->create_KeyExpansion(_key);
}

AES::AES(const AESkey& ak) :key(ak), Nk((int)ak.get_LenBytes() >> 2), Nr(Nk+6),
    keyExpLen((Nr+1)<<4) {
    char* _key = new char[ak.get_LenBytes()];
    ak.write_Key(_key);
    this->create_KeyExpansion(_key);

    delete[] _key;
}

AES::AES(const AES& a) : key(a.key), Nk(a.Nk), Nr(a.Nr),
    keyExpLen(a.keyExpLen) {
    this->keyExpansion = new char[(unsigned)a.keyExpLen];
    for(int i = 0; i < a.keyExpLen; i++)
        this->keyExpansion[i] = a.keyExpansion[i];
}

AES::~AES() {
    if(keyExpansion != NULL) delete[] keyExpansion;
    keyExpansion = NULL;
}

AES& AES::operator = (const AES& a) {
    if(this != &a) {
        this->key = a.key;
        this->Nk = a.Nk;
        this->Nr = a.Nr;
        this->keyExpLen = a.keyExpLen;
        if(this->keyExpansion != NULL) delete[] keyExpansion;
        this->keyExpansion = new char[(unsigned)a.keyExpLen];
        for(int i = 0; i < a.keyExpLen; i++)
            this->keyExpansion[i] = a.keyExpansion[i];
    }
    return *this;
}

void AES::create_KeyExpansion(const char* const _key) {
    char temp[4];         // (Nr+1)*16
	int i, keyExpansionLen = this->keyExpLen;// Key expansion length in bytes

	keyExpansion = new char[(unsigned)keyExpansionLen];
	keyExpansionLen >>= 2; // keyExpansionLen in words (block of 4 bytes)
	// ^~~ == keyExpansionLen /= 4;

	bool debug = false; // -Show the construction of the key expansion.

	// -The first Nk words of the key expansion are the key itself.
	int NkBytes = Nk << 2; // Nk * 4
	for(i = 0; i < NkBytes; i++) keyExpansion[i] = _key[i];

	if(debug) {
	    std::cout <<
	    "-------------------------------------------------- Key Expansion --------------------------------------------------\n"
	    "-------------------------------------------------------------------------------------------------------------------\n"
	    "    |               |     After     |     After     |               |   After XOR   |               |     w[i] =   \n"
        " i  |     temp      |   RotWord()   |   SubWord()   |  Rcon[i/Nk]   |   with Rcon   |    w[i-Nk]    |   temp xor   \n"
        "    |               |               |               |               |               |               |    w[i-Nk]   \n"
        "-------------------------------------------------------------------------------------------------------------------\n";
	}

	for(i = Nk; i < keyExpansionLen; i++) {
		// -Guarding against modify things
		//   that we don't want to modify.
		CopyWord(&(keyExpansion[(i - 1) << 2]), temp);
        if(debug) {
            std::cout << " " << i;
            i < 10 ? std::cout << "  | " : std::cout << " | ";
		    printWord(temp);
        }
		// -i is a multiple of Nk, witch value is 8
		if((i % Nk) == 0) {
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
			    printWord(Rcon[i/Nk - 1]);
			}
			XORword(temp, Rcon[i/Nk -1], temp);
			if(debug) {
			    std::cout << " | ";
			    printWord(temp);
			}
		} else {
		    if(Nk > 6 && (i % Nk) == 4) {
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
			printWord(&(keyExpansion[(i - Nk) << 2]));
		}
		XORword(&(keyExpansion[(i - Nk) << 2]),temp, &(keyExpansion[i << 2]));
		if(debug) {
			std::cout << " | ";
			printWord(&(keyExpansion[i << 2]));
		}
		if(debug )std::cout << '\n';
	}
	if(debug) std::cout << "--------------------------------------------------"
	"-----------------------------------------------------------------\n\n";
	debug = false;
}

void AES::printWord(const char word[4]) {
    unsigned int temp = 0;
	std::cout << '[';
	for(int i = 0; i < 4; i++) {
	    temp = (ui08)0xFF & (ui08)word[i];
		if(temp < 16) std::cout << '0';
		printf("%X", temp);
		if(i != 3)
			std::cout << ",";
	}
	std::cout << ']';
}

void AES::encryptCBC(char*const data,unsigned size, char IVlocation[16])const{
    char *previousBlk, *currentBlk = data;
    int numofBlocks = (int)size >> 4;  //  numofBlocks = size / 16.
    int rem = (int)size & 15, i;       // -Bytes remaining rem = size % 16

    this->key.set_OperationMode(AESkey::CBC); // -Setting operation mode.
    setIV(IVlocation);                        // -Setting initial vector.
    this->key.set_IV(IVlocation);

    // -Encryption of the first block.
    XORblocks(currentBlk, IVlocation, currentBlk);
    encryptBlock(currentBlk);

    // -Encryption of the rest of the blocks.
    for(i = 1; i < numofBlocks; i++) {
        previousBlk = currentBlk;
        currentBlk += 16;
        XORblocks(currentBlk, previousBlk, currentBlk);
        encryptBlock(currentBlk);
    }
    // -This part of the code is for encrypt data that its size is not
    //  multiple of 16. This is not specified in the NIST standard.
    if(rem != 0) {
        previousBlk = currentBlk;
        currentBlk += 16;
        for(i=0; i<rem; i++) currentBlk[i] = currentBlk[i] ^ previousBlk[i];
        encryptBlock(previousBlk + rem);
    }
}


void AES::decryptCBC(char*const data, unsigned size, const char IV[16]) const{
    if(size == 0) return;
    char *currentBlk = data, previousBlk[16], cipherCopy[16];
    int numofBlocks = (int)size >> 4; // numofBlocks = size / 16
    int rem = (int)size & 15;         // -Rest of the bytes rem = size % 16
    int i;

    for(i = 0; i < 16; i++) cipherCopy[i] = IV[i];
    CopyBlock(currentBlk, previousBlk); // -Copying the first ciphered block.

    // -Deciphering the first block.
    decryptBlock(currentBlk);
    XORblocks(currentBlk, cipherCopy, currentBlk);

    // -Decryption of the rest of the blocks.
    // -Last block is going to be processed differently.
    if(numofBlocks > 0) numofBlocks--;
    for(i = 1; i < numofBlocks; i++) {
        currentBlk += 16;
        // -Saving cipher block for the next round.
        CopyBlock(currentBlk, cipherCopy);
        decryptBlock(currentBlk);
        XORblocks(currentBlk, previousBlk, currentBlk);
        // -Cipher block now becomes previous block.
        CopyBlock(cipherCopy, previousBlk);
    }
    currentBlk += 16;
    if(rem == 0) { // -Data size is a multiple of 16.
        decryptBlock(currentBlk);
        XORblocks(currentBlk, previousBlk, currentBlk);
    } else {      // -Data size isn't a multiple of 16.
        decryptBlock(currentBlk + rem);
        for(i = 0; i < rem; i++)
            currentBlk[i+16] = currentBlk[i+16] ^ currentBlk[i];
        decryptBlock(currentBlk);
        XORblocks(currentBlk, previousBlk, currentBlk);
    }
}

// Naive way of setting the initial vector.
void AES::setIV(char IV[16]) const {
    intToChar ic;
    ic.integer = time(NULL);
    int i, j, k;
    for(i = 0; i < 4; i++, ic.integer++) {
        k = i << 2; // k = i * 4
        for(j = 0; j < 4; j++)
            IV[k + j] = ic.chars[j];
    }
    encryptBlock(IV);
}

void AES::XORblocks(char b1[16], char b2[16], char r[16]) const {
    for(int i = 0; i < 16; i++) r[i] = b1[i] ^ b2[i];
}

void AES::printState(const char state[16]) {
	int i, j, temp;
	for(i = 0; i < 4; i++) {
		std::cout << '[';
		for(j = 0; j < 4; j++) {
		    temp = (unsigned char)0xFF & (unsigned char)state[(j << 2) + i];
			if(temp < 16) std::cout << '0';
			printf("%X", temp);
			if(j != 3) std::cout << ", ";
		}
		std::cout << "]\n";
	}
}

void AES::CopyWord(const char source[4], char destination[4]) const {
    for(int i = 0; i < 4; i++) destination[i] = source[i];
}

void AES::CopyBlock(const char source[16], char destination[16]) const {
    for(int i = 0; i < 16; i++) destination[i] = source[i];
}

void AES::XORword(const char w1[4], const char w2[4], char resDest[4])
const{
    for(int i = 0; i < 4; i++) resDest[i] = w1[i] ^ w2[i];
}

void AES::RotWord(char word[4]) const{
    char temp = word[0]; int i;
	for(i = 0; i < 3; i++) word[i] = word[i + 1];
	word[3] = temp;
}

void AES::SubWord(char word[4]) const{
    for(int i = 0; i < 4; i++) word[i] = (char)SBox[(ui08)word[i]];
}

// -Applies a substitution table (S-box) to each char.
void AES::SubBytes(char state[16]) const{
	for(int i = 0; i < 16; i++) state[i] = (char)SBox[(ui08)state[i]];
}

// -Shift rows of the state array by different offset.
void AES::ShiftRows(char state[16]) const{
	int i, j; char tmp[4];
	for(i = 1; i < 4; i++) {
		for(j = 0; j < 4; j++)
			tmp[j] = state[i + (j << 2)];
		for(j = 0; j < 4; j++)
			state[i + (j << 2)] = tmp[(j + i) & 3];
	}
}

// -Mixes the data within each column of the state array.
void AES::MixColumns(char state[16]) const{
    int i, I, j, k;
	char temp[4];
	for(i = 0; i < 4; i++) {
	    I = i << 2; // I = i * 4;
		for(k = 0; k < 4; k++) temp[k] = state[I + k]; // Copying row.
		for(j = 0; j < 4; j++) {
		    // -First state column element times matrix first column
			state[I + j] = (char)
			multiply[ (int)(ui08)a[(4 - j) & 3] ][ (int)(ui08)temp[0] ];
			for(k = 1; k < 4; k++) {
				state[I + j] ^= (char)
				multiply[ (int)(ui08)a[(k - j + 4)&3] ][ (int)(ui08)temp[k] ];
			}
		}
	}
}

// -Combines a round key with the state.
void AES::AddRoundKey(char state[16], int round) const{
    round <<= 4; // -Each round uses 16 bytes and r <<= 4 == r *= 16.
	for(int i = 0; i < 16; i++) state[i] ^= keyExpansion[round + i];
}

void AES::encryptBlock(char block[]) const {
	int i, j;

	bool debug = false; // True to show every encryption step.

	// -Debugging purposes.
	// -Columns of the debugging table.
	char *SOR, *ASB, *ASR, *AMC;
	SOR = ASB = ASR = AMC = NULL;

	if(debug) {     // (Nr + 2) * 16
        SOR = new char[(unsigned)(Nr + 2) << 4];
        AMC = new char[(unsigned)(Nr - 1) << 4];
        ASB = new char[(unsigned)Nr << 4];
        ASR = new char[(unsigned)Nr << 4];
	}

    if(debug) for(j = 0; j < 16; j++) SOR[j] = block[j];
	AddRoundKey(block, 0);
	if(debug) for(j = 0; j < 16; j++) SOR[j + 16] = block[j];

	for(i = 1; i < Nr; i++) {
		SubBytes(block);
		if(debug) for(j = 0; j < 16; j++) ASB[((i - 1) << 4) + j] = block[j];

		ShiftRows(block);
		if(debug) for(j = 0; j < 16; j++) ASR[((i - 1) << 4) + j] = block[j];

		MixColumns(block);
		if(debug) for(j = 0; j < 16; j++) AMC[((i - 1) << 4) + j] = block[j];

		AddRoundKey(block, i);
		if(debug) for(j = 0; j < 16; j++) SOR[((i + 1) << 4) + j] = block[j];
	}
	SubBytes(block);
	if(debug) for(j = 0; j < 16; j++) ASB[((i - 1) << 4) + j] = block[j];

	ShiftRows(block);
	if(debug) for(j = 0; j < 16; j++) ASR[((i - 1) << 4) + j] = block[j];

	AddRoundKey(block, i);
	if(debug) for(j = 0; j < 16; j++) SOR[((i + 1) << 4) + j] = block[j];

	if(debug) {
	    auto printBlockRow = [] (const char blk[16], int row) {
	        unsigned int temp = 0;
            std::cout << '[';
	        for(int i = 0; i < 16; i += 4) {
	            temp = (ui08)0xFF & (ui08)blk[row + i];
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

void AES::InvSubBytes(char state[16]) const{
    for(int i = 0; i < 16; i++) state[i] = (char)InvSBox[(ui08)state[i]];
}

void AES::InvShiftRows(char state[16]) const{
    int i, j; char temp[4];
	for(i = 1; i < 4; i++) {
		for(j = 0; j < 4; j++)
			temp[j] = state[i + (j << 2)];
		for(j = 0; j < 4; j++)
			state[(j << 2) + i] = temp[(j - i + 4) & 3];
	}
}

void AES::InvMixColumns(char state[16]) const{
    int  i, j, k, I;
	char temp[4];
	for(i = 0; i < 4; i ++) {
	    I = i << 2; // I = i * 4
		for(j = 0; j < 4; j++)
			temp[j] = state[I + j];
		for(j = 0; j < 4; j++) {
			state[I + j] = (char)
			multiply[ (int)(ui08)aInv[(4 - j) & 0x03] ][ (int)(ui08)temp[0] ];
			for(k = 1; k < 4; k++)
				state[I + j] ^= (char)
				multiply[(int)(ui08)aInv[(k - j + 4)&3] ][ (int)(ui08)temp[k]];
		}
	}
}

void AES::decryptBlock(char block[16]) const {
    int i = Nr;
	AddRoundKey(block, i);
	for(i--; i > 0; i--) {
		InvShiftRows(block);
		InvSubBytes(block);
		AddRoundKey(block, i);
		InvMixColumns(block);
	}
	InvShiftRows(block);
	InvSubBytes(block);
	AddRoundKey(block, 0);
}

