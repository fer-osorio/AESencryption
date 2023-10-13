#include<iostream>
#include<ctime>
#include"AES_256.hpp"

AES_256::AES_256(char key[32]) {
    if(key == NULL) {
        key = defaultKey;
    }
    char temp[4];
	int i, keyLen = 32;
	int keyExpansionLen = 60; // -Length of the key expansion in words.

	bool debug = false; // -Show the construction of the key expansion.

	// -The first 8 words are the key itself.
	for(i = 0; i < keyLen; i++) keyExpansion[i] = key[i];

	if(debug) {
	    std::cout <<
	    "-------------------------------------------------- Key Expansion --------------------------------------------------\n"
	    "-------------------------------------------------------------------------------------------------------------------\n"
	    "    |               |     After     |     After     |               |   After XOR   |               |     w[i] =   \n"
        " i  |     temp      |   RotWord()   |   SubWord()   |  Rcon[i/Nk]   |   with Rcon   |    w[i-Nk]    |   temp xor   \n"
        "    |               |               |               |               |               |               |    w[i-Nk]   \n"
        "-------------------------------------------------------------------------------------------------------------------\n";
	}

	for(i = 8; i < keyExpansionLen; i++) {
		// -Guarding against modify things
		//   that we don't want to modify.
		CopyWord(&(keyExpansion[(i - 1) << 2]), temp);
        if(debug) {
            std::cout << " " << i;
            i < 10 ? std::cout << "  | " : std::cout << " | ";
		    printWord(temp);
        }
		// -i is a multiple of Nk, witch value is 8
		if((i & 7) == 0) { // i & 7 == i % 8.
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
		    if((i & 7) == 4) {
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

void AES_256::printWord(const char word[4]) {
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

int AES_256::encryptCBC(char* data_ptr, int size) const {
    // -Padding process needed. Supposing that size as a multiple of 16.
    char IV[16], *prevblk;        // -Initial vector and previous block.
    int numofBlocks = size >> 4;  //  numofBlocks = size / 16.
    int rem = size & 15;          // -Bytes remaining rem = size % 16
    int iv = setIV(IV), i;        // -Setting initial vector.

    // -Encryption of the first block.
    XORblocks(data_ptr, IV, data_ptr);
    encryptBlock(data_ptr);

    // -Encryption of the rest of the blocks.
    for(i = 1; i < numofBlocks; i++) {
        prevblk = data_ptr;
        data_ptr += 16;
        XORblocks(data_ptr, prevblk, data_ptr);
        encryptBlock(data_ptr);
    }
    // -This part of the code is for encrypt data that its size is not
    //  multiple of 16. This is not specified in the NIST standard.
    if(rem != 0) {
        prevblk = data_ptr;
        data_ptr += 16;
        for(i = 0; i < rem; i++) data_ptr[i] = data_ptr[i] ^ prevblk[i];
        encryptBlock(prevblk + rem);
    }

    return iv;
}

void AES_256::decryptCBC(char* data_ptr, int size, int _iv) const {
    char CB[16], prevCB[16];     // -Cipher block and previous cipher block.
    int numofBlocks = size >> 4; // -Number of blocks numofBlocks = size / 16
    int rem = size & 15;         // -Rest of the bytes rem = size % 16
    int i;

    getIV(_iv, CB);              // -Getting the initial vector.
    CopyBlock(data_ptr, prevCB); // -Copying the first ciphered block.

    // -Deciphering the first block.
    decryptBlock(data_ptr);
    XORblocks(data_ptr, CB, data_ptr);

    // -Decryption of the rest of the blocks.
    numofBlocks--; // -Last hole block is going to be processed differently.
    for(i = 1; i < numofBlocks; i++) {
        data_ptr += 16;
        CopyBlock(data_ptr, CB); // -Saving cipher block for the next round.
        decryptBlock(data_ptr);
        XORblocks(data_ptr, prevCB, data_ptr);
        CopyBlock(CB, prevCB);
    }
    data_ptr += 16;
    if(rem == 0) { // -Data size is a multiple of 16.
        decryptBlock(data_ptr);
        XORblocks(data_ptr, prevCB, data_ptr);
    } else {      // -Data size isn't a multiple of 16.
        decryptBlock(data_ptr + rem);
        for(i = 0; i < rem; i++) data_ptr[i+16] = data_ptr[i+16] ^ data_ptr[i];
        decryptBlock(data_ptr);
        XORblocks(data_ptr, prevCB, data_ptr);
    }
}

int AES_256::setIV(char IV[16]) const {
    int FF = 255, iv = time(NULL), i, j, k;
    for(i = 0; i < 4; i++, iv++) {
        k = i << 2; // k = i * 4
        for(j = 0; j < 4; j++)// j * 8
            IV[k + j] = char ((iv >> (j << 3)) & FF);
    }
    encryptBlock(IV);
    return iv-4;
}

void AES_256::getIV(int _iv, char IV[16]) const {
    int FF = 255, i, j, k;
    for(i = 0; i < 4; i++, _iv++) {
        k = i << 2;
        for(j = 0; j < 4; j++)
            IV[k + j] = char ((_iv >> (j << 3)) & FF);
    }
    encryptBlock(IV);
}

void AES_256::XORblocks(char b1[16], char b2[16], char r[16]) const {
    for(int i = 0; i < 16; i++) r[i] = b1[i] ^ b2[i];
}

void AES_256::printState(const char state[16]) {
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

void AES_256::CopyWord(const char source[4], char destination[4]) const {
    for(int i = 0; i < 4; i++) destination[i] = source[i];
}

void AES_256::CopyBlock(const char source[16], char destination[16]) const {
    for(int i = 0; i < 16; i++) destination[i] = source[i];
}

void AES_256::XORword(const char w1[4], const char w2[4], char resDest[4])
const{
    for(int i = 0; i < 4; i++) resDest[i] = w1[i] ^ w2[i];
}

void AES_256::RotWord(char word[4]) const{
    char temp = word[0]; int i;
	for(i = 0; i < 3; i++) word[i] = word[i + 1];
	word[3] = temp;
}

void AES_256::SubWord(char word[4]) const{
    for(int i = 0; i < 4; i++) word[i] = (char)SBox[(ui08)word[i]];
}

// -Applies a substitution table (S-box) to each char.
void AES_256::SubBytes(char state[16]) const{
	for(int i = 0; i < 16; i++) state[i] = (char)SBox[(ui08)state[i]];
}

// -Shift rows of the state array by different offset.
void AES_256::ShiftRows(char state[16]) const{
	int i, j; char tmp[4];
	for(i = 1; i < 4; i++) {
		for(j = 0; j < 4; j++)
			tmp[j] = state[i + (j << 2)];
		for(j = 0; j < 4; j++)
			state[i + (j << 2)] = tmp[(j + i) & 3];
	}
}

// -Mixes the data within each column of the state array.
void AES_256::MixColumns(char state[16]) const{
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
void AES_256::AddRoundKey(char state[16], int round) const{
    round <<= 4; // -Each round uses 16 bytes and r << 4 == r *= 16.
	for(int i = 0; i < 16; i++) state[i] ^= keyExpansion[round + i];
}

void AES_256::encryptBlock(char block[]) const {
	int i, j;

	bool debug = false; // True to show every encryption step.

	// -Debugging purposes.
	// -Columns of the debugging table.
	char *SOR, *ASB, *ASR, *AMC;
	SOR = ASB = ASR = AMC = NULL;

	if(debug) {     // (Nr + 2) * 16
        SOR = new char[(Nr + 2) << 4];
        AMC = new char[(Nr - 1) << 4];
        ASB = new char[Nr << 4];
        ASR = new char[Nr << 4];
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

void AES_256::InvSubBytes(char state[16]) const{
    for(int i = 0; i < 16; i++) state[i] = (char)InvSBox[(ui08)state[i]];
}

void AES_256::InvShiftRows(char state[16]) const{
    int i, j; char temp[4];
	for(i = 1; i < 4; i++) {
		for(j = 0; j < 4; j++)
			temp[j] = state[i + (j << 2)];
		for(j = 0; j < 4; j++)
			state[(j << 2) + i] = temp[(j - i + 4) & 3];
	}
}

void AES_256::InvMixColumns(char state[16]) const{
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

void AES_256::decryptBlock(char block[16]) const {
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
	//printState(block);
}

