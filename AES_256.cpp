#include<iostream>
#include"AES_256.hpp"

AES_256::AES_256(char key[32]) {
    char temp[4];
	int i, keyLen = 32;
	int keyExpansionLen = 60; // -Length of the key expansion in words.

	bool debug = true; // -Show the construction of the key expansion.

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

void AES_256::CopyWord(const char source[4], char destination[4]) {
    for(int i = 0; i < 4; i++) destination[i] = source[i];
}

void AES_256::XORword(const char w1[4], const char w2[4], char resDest[4]) {
    for(int i = 0; i < 4; i++) resDest[i] = w1[i] ^ w2[i];
}

void AES_256::RotWord(char word[4]) {
    char temp = word[0]; int i;
	for(i = 0; i < 3; i++) word[i] = word[i + 1];
	word[3] = temp;
}

void AES_256::SubWord(char word[4]) {
    for(int i = 0; i < 4; i++) word[i] = (char)SBox[(ui08)word[i]];
}

// -Applies a substitution table (S-box) to each char.
void AES_256::SubBytes(char state[16]) {
	for(int i = 0; i < 16; i++) state[i] = (char)SBox[(ui08)state[i]];
}

// -Shift rows of the state array by different offset.
void AES_256::ShiftRows(char state[16]) {
	int i, j; char tmp[4];
	for(i = 1; i < 4; i++) {
		for(j = 0; j < 4; j++)
			tmp[j] = state[i + (j << 2)];
		for(j = 0; j < 4; j++)
			state[i + (j << 2)] = tmp[(j + i) & 3];
	}
}

// -Mixes the data within each column of the state array.
void AES_256::MixColumns(char state[16]) {
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
void AES_256::AddRoundKey(char state[16], int round) {
    round <<= 4; // -Each round uses 16 bytes and r << 4 == r *= 16.
	for(int i = 0; i < 16; i++) state[i] ^= keyExpansion[round + i];
}

void AES_256::encryptBlock(char block[]) {
	int i, j;

	bool debug = true; // True to show every encryption step.

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

void AES_256::InvSubBytes(char state[16]) {
    for(int i = 0; i < 16; i++) state[i] = (char)InvSBox[(ui08)state[i]];
}

void AES_256::InvShiftRows(char state[16]) {
    int i, j; char temp[4];
	for(i = 1; i < 4; i++) {
		for(j = 0; j < 4; j++)
			temp[j] = state[i + (j << 2)];
		for(j = 0; j < 4; j++)
			state[(j << 2) + i] = temp[(j - i + 4) & 3];
	}
}

void AES_256::InvMixColumns(char state[16]) {
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

