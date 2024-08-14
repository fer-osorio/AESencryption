#include<fstream>
#include"AES.hpp"
#include"OperationsGF256.hpp"

using namespace AES;

/****************************************** Multiplication of two numbers of 256 bits to obtain a 512 bits number ************************************************/

union intToChar {
    int integer;                                                                // Useful when casting from a 32 bits integer to an array of four chars
    char chars[4];
};
union uint64_uint32 {                                                           // -Useful for a casting from a 64 bits unsigned integer to an array of two 32 bits
    unsigned long long uint64;                                                  //  integer
    unsigned uint32[2];
};
union _16uint32_64uchar {                                                        // -Representing 256 bits in an union of 8 unsigned int and 32 char
    unsigned uint32[16];
    unsigned char chars[64];
};
struct UnsignedInt256bits {
    union { unsigned char chars[32]; unsigned uint32[8]; } NumberPlaces = {0,0,0,0,0,0,0,0}; // -256 bits in a anonymous union of 8 unsigned int and 32 char

    UnsignedInt256bits() {}
    UnsignedInt256bits(const char*const data) { for(int i = 0; i < 32; i++) NumberPlaces.chars[i] = (unsigned char)data[i]; }

    unsigned operator [] (int i) const {
        if(i < 0 || i >= 8) i &= 7;                                             // -i&7 is equivalent to i%8
        return this->NumberPlaces.uint32[i];
    }
    void reWriteLeastSignificantBytes(const char*const array, unsigned arraySize = 32) {    // -Rewrites the least significant bytes of the NumberPlaces union.
        unsigned i;                                                             // -Writing the array from left to right, those bytes would be the left ones.
        if(arraySize > 32) arraySize &= 31;                                     // -arraySize % 32
        for(i = 0; i < arraySize; i++)
            this->NumberPlaces.chars[i] = (unsigned char)array[i];              // -The rest of the bytes (i >= arraySize) are left untouched
    }
};

_16uint32_64uchar operator * (const UnsignedInt256bits& a, const UnsignedInt256bits& b) { // -Multiplying two integers of 256 bits each one
    int i, j;
    unsigned carriage = 0;
    uint64_uint32 buff = {0};
    _16uint32_64uchar result = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};               // -The result will need 512 bits (for arbitrary arguments)

    for(i = 0; i < 8 ; i++) {                                                   // -Implementing pencil and paper algorithm
        for(j = 0; j < 8; j++) {
            buff.uint64 = (unsigned long long)a[i] * b[j] + result.uint32[i+j] + carriage;
            result.uint32[i+j] = buff.uint32[0];                                // -Equivalent to obtaining the modulus 2^32
            carriage = buff.uint32[1];                                          // -Equivalent to obtaining the quotient 2^32
        }
        result.uint32[i+j] = carriage;
        carriage = 0;
    }
    return result;
}


/************************************************************** Handling AES cryptographic keys ******************************************************************/

Key::Key(const char* const _key, Length len, OperationMode _operation_mode, const char* const _IV):
    operation_mode(_operation_mode), length(len), lengthBytes((unsigned)len >> 3) {
    unsigned i;
    this->key = new char[this->lengthBytes];
    if(_key != NULL) for(i = 0; i < this->lengthBytes; i++) this->key[i] = _key[i];
    if(_IV != NULL)  for(i = 0; i < 16; i++) this->IV[i] = _IV[i];
}

Key::Key(const Key& ak):operation_mode(ak.operation_mode), length(ak.length), lengthBytes(ak.lengthBytes) {
    unsigned i;
    this->key = new char[ak.lengthBytes];
    for(i = 0; i < ak.lengthBytes; i++) this->key[i] = ak.key[i];               // -Supposing Cipher object is well constructed, this is, ak.key != NULL
    if(ak.operation_mode == CBC) for(i=0; i < 16; i++) this->IV[i]=ak.IV[i];    // -Without CBC, copying IV is pointless.
}

Key& Key::operator = (const Key& ak) {
    if(this != &ak) {
        unsigned i;
        this->length   = ak.length;
        this->lengthBytes = ak.lengthBytes;
        if(this->key != NULL) delete[] this->key;
        this->key = new char[ak.lengthBytes];
        for(i = 0; i < ak.lengthBytes; i++) this->key[i] = ak.key[i];
        if(ak.operation_mode == CBC)                                            // -Without CBC, copying IV is pointless.
            for(i = 0; i < 16; i++) this->IV[i] = ak.IV[i];
    }
    return *this;
}

Key::Key(const char*const fname): operation_mode(ECB), length(_128), lengthBytes(16) { // -Building from .key file
    char AESKEY[6];
    char opMode[3];
    short len;
    std::ifstream file;
    file.open(fname, std::ios::binary);
    if(file.is_open()) {
        file.read((char*)AESKEY, 6);                                            // -Determining if file is a .key file
        if(AESKEY[0] == 'A' || AESKEY[1] == 'E' || AESKEY[2] == 'S' || AESKEY[3] == 'K' || AESKEY[4] == 'E' || AESKEY[5] == 'Y') {
                file.read((char*)opMode, 3);                                    // -Determining operation mode
                if(opMode[0]=='E' && opMode[1]=='C' && opMode[2]=='B')
                    this->operation_mode = ECB;
                else if(opMode[0]=='C' && opMode[1]=='B' && opMode[2]=='C')
                    this->operation_mode = CBC;
                else if(opMode[0]=='C' && opMode[1]=='F' && opMode[2]=='B')
                    this->operation_mode = CFB;
                else if(opMode[0]=='O' && opMode[1]=='F' && opMode[2]=='B')
                    this->operation_mode = OFB;
                else if(opMode[0]=='C' && opMode[1]=='T' && opMode[2]=='R')
                    this->operation_mode = CTR;
                else if(opMode[0]=='P' && opMode[1]=='V' && opMode[2]=='S')
                    this->operation_mode = PVS;
                else throw "Could not recognize operation mode...";

                file.read((char*)&len, 2);                                      // -Reading key length
                if(len == 128 || len == 192 || len == 256)
                    this->length = (Length)len;
                else throw "Key length not allowed...";
                this->lengthBytes = (unsigned)len >> 3;                         // -lengthBytes = len / 8;

                this->key = new char[this->lengthBytes];                        // -Reading key
                file.read(this->key, this->lengthBytes);

                if(this->operation_mode == CBC) file.read((char*)this->IV, 16); // -In CBC case, reading IV.
           } else {
                throw "Not a valid AES key file...";
           }
    } else {
        throw "Could not open the file...";
    }
}

Key::~Key() {
    if(this->key != NULL) delete[] this->key;
    this->key = NULL;
}

void Key::save(const char* const fname) const {
    const char* aeskey = "AESKEY";                                              // File type.
    const char* op_mode;
    switch(this->operation_mode) {                                              // -Operation mode.
        case ECB:
            op_mode = "ECB";
            break;
        case CBC:
            op_mode = "CBC";
            break;
        case CFB:
            op_mode = "CFB";
            break;
        case OFB:
            op_mode = "OFB";
            break;
        case CTR:
            op_mode = "CTR";
            break;
        case PVS:
            op_mode = "PVS";
            break;
        default:
            throw "Could not recognize operation mode...";
    }
    std::ofstream file;
    file.open(fname, std::ios::binary);
    if(file.is_open()) {
        file.write(aeskey,  6);                                                 // -File type
        file.write(op_mode, 3);                                                 // -Operation mode
        std::cout << "File Source/AES.cpp, function void Key::save(const char* const fname) const. Operation mode = ";
        for(int i = 0; i < 3; i++) std::cout << op_mode[i];
        std::cout << '\n';
        file.write((char*)&this->length, 2);                                    // -Key length in bits
        file.write(this->key, this->lengthBytes);                               // -Key
        if(this->operation_mode == CBC) file.write(this->IV, 16);               // -If CBC, writes initial vector
    } else {
        throw "File could not be written.";
    }
}


/************************************************** AES encryption and decryption algorithms implementation ******************************************************/

Cipher::Cipher(const char* const _key, Key::Length len): key(_key, len, Key::ECB), Nk(len >> 5), Nr(Nk+6), keyExpLen((Nr+1)<<4) {
    this->create_KeyExpansion(_key);
}

Cipher::Cipher(const Key& ak) :key(ak), Nk((int)ak.getLengthBytes() >> 2), Nr(Nk+6), keyExpLen((Nr+1)<<4) {
    char* _key = new char[ak.getLengthBytes()];
    ak.write_Key(_key);
    this->create_KeyExpansion(_key);
    delete[] _key;
}

Cipher::Cipher(const Cipher& a) : key(a.key), Nk(a.Nk), Nr(a.Nr), keyExpLen(a.keyExpLen) {
    this->keyExpansion = new char[(unsigned)a.keyExpLen];
    for(int i = 0; i < a.keyExpLen; i++) this->keyExpansion[i] = a.keyExpansion[i];
}

Cipher::~Cipher() {
    if(keyExpansion != NULL) delete[] keyExpansion;
    keyExpansion = NULL;
}

Cipher& Cipher::operator = (const Cipher& a) {
    if(this != &a) {
        this->key = a.key;
        this->Nk = a.Nk;
        this->Nr = a.Nr;
        this->keyExpLen = a.keyExpLen;
        if(this->keyExpansion != NULL) delete[] keyExpansion;
        this->keyExpansion = new char[(unsigned)a.keyExpLen];
        for(int i = 0; i < a.keyExpLen; i++) this->keyExpansion[i] = a.keyExpansion[i];
    }
    return *this;
}

void Cipher::create_KeyExpansion(const char* const _key) {
    char temp[4];                                                               // (Nr+1)*16
	int i, keyExpansionLen = this->keyExpLen;                                   // Key expansion length in bytes

	keyExpansion = new char[(unsigned)keyExpansionLen];
	keyExpansionLen >>= 2;                                                      // keyExpansionLen in words (block of 4 bytes). keyExpansionLen /= 4

	bool debug = false;                                                         // -Show the construction of the key expansion.

	int NkBytes = Nk << 2;                                                      // -The first Nk words of the key expansion are the key itself. // Nk * 4
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
		CopyWord(&(keyExpansion[(i - 1) << 2]), temp);                          // -Guarding against modify things that we don't want to modify.
        if(debug) {
            std::cout << " " << i;
            i < 10 ? std::cout << "  | " : std::cout << " | ";
		    printWord(temp);
        }
		if((i % Nk) == 0) {                                                     // -i is a multiple of Nk, witch value is 8
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

void Cipher::printWord(const char word[4]) {
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

void Cipher::encryptECB(char*const data, unsigned size) const{
    if(size == 0) return;                                                       // Exception here.
    this->key.set_OperationMode(Key::ECB);                                      // -Setting operation mode.

    char* currentDataBlock = data;
    int numofBlocks = int(size >> 4);                                           //  numofBlocks = size / 16.
    int rem = int(size & 15), i;                                                // -Bytes remaining rem = size % 16

    --numofBlocks;                                                              // Last block will be treated differently.
    for(i = 0; i < numofBlocks; i++) {
        encryptBlock(currentDataBlock);
        currentDataBlock += 16;
    }
    if(rem != 0) {                                                              // -This part of the code is for encrypt data that its size is not multiple of 16.
        encryptBlock(currentDataBlock);                                         //  This is not specified in the NIST standard.
        encryptBlock(currentDataBlock + rem);                                   // -Not handling the case size < 16
        return;
    }
    encryptBlock(currentDataBlock);
}

void Cipher::decryptECB(char *const data, unsigned int size) const{
    if(size == 0) return;                                                       // Exception here.

    char* currentDataBlock = data;
    int numofBlocks = int(size >> 4);                                           //  numofBlocks = size / 16.
    int rem = int(size & 15), i;                                                // -Bytes remaining rem = size % 16

    --numofBlocks;                                                              // Last block will be treated differently.
    for(i = 0; i < numofBlocks; i++) {
        decryptBlock(currentDataBlock);
        currentDataBlock += 16;
    }
    if(rem != 0) {                                                              // -This part of the code is for encrypt data that its size is not multiple of 16.
        decryptBlock(currentDataBlock + rem);                                   //  This is not specified in the NIST standard.
        decryptBlock(currentDataBlock);                                         // -Not handling the case size < 16
        return;
    }
    decryptBlock(currentDataBlock);
}

void Cipher::encryptCBC(char*const data,unsigned size) const {
    if(size == 0) return;                                                       // Exception here.
    this->key.set_OperationMode(Key::CBC);                                      // -Setting operation mode.

    char *previousBlk, *currentDataBlock = data;
    char IVlocation[16];
    int numofBlocks = (int)size >> 4;                                           //  numofBlocks = size / 16.
    int rem = (int)size & 15, i;                                                // -Bytes remaining rem = size % 16

    setIV(IVlocation);                                                          // -Setting initial vector.
    this->key.set_IV(IVlocation);
    XORblocks(currentDataBlock, IVlocation, currentDataBlock);                  // -Encryption of the first block.
    encryptBlock(currentDataBlock);

    for(i = 1; i < numofBlocks; i++) {                                          // -Encryption of the rest of the blocks.
        previousBlk = currentDataBlock;
        currentDataBlock += 16;
        XORblocks(currentDataBlock, previousBlk, currentDataBlock);
        encryptBlock(currentDataBlock);
    }
    if(rem != 0) {                                                              // -This part of the code is for encrypt data that its size is not multiple of 16.
        previousBlk = currentDataBlock;                                         //  This is not specified in the NIST standard.
        currentDataBlock += 16;
        for(i=0; i<rem; i++) currentDataBlock[i] = currentDataBlock[i] ^ previousBlk[i];
        encryptBlock(previousBlk + rem);
    }
}


void Cipher::decryptCBC(char*const data, unsigned size) const{
    if(size == 0) return;                                                       // Exception here.

    char *currentDataBlock = data, previousBlk[16], cipherCopy[16];
    int numofBlocks = (int)size >> 4;                                           // numofBlocks = size / 16
    int rem = (int)size & 15;                                                   // -Rest of the bytes rem = size % 16
    int i;

    //for(i = 0; i < 16; i++) cipherCopy[i] = this->key.getIV()[i];
    this->key.write_IV(cipherCopy);
    CopyBlock(currentDataBlock, previousBlk);                                   // -Copying the first ciphered block.

    decryptBlock(currentDataBlock);                                             // -Deciphering the first block.
    XORblocks(currentDataBlock, cipherCopy, currentDataBlock);

    if(numofBlocks > 0) numofBlocks--;                                          // -Last block is going to be processed differently.
    for(i = 1; i < numofBlocks; i++) {                                          // -Decryption of the rest of the blocks.
        currentDataBlock += 16;
        CopyBlock(currentDataBlock, cipherCopy);                                // -Saving cipher block for the next round.
        decryptBlock(currentDataBlock);
        XORblocks(currentDataBlock, previousBlk, currentDataBlock);
        CopyBlock(cipherCopy, previousBlk);                                     // -Cipher block now becomes previous block.
    }
    currentDataBlock += 16;
    if(rem == 0) {                                                              // -Data size is a multiple of 16.
        decryptBlock(currentDataBlock);
        XORblocks(currentDataBlock, previousBlk, currentDataBlock);
    } else {                                                                    // -Data size isn't a multiple of 16.
        decryptBlock(currentDataBlock + rem);
        for(i = 0; i < rem; i++)
            currentDataBlock[i+16] = currentDataBlock[i+16] ^ currentDataBlock[i];
        decryptBlock(currentDataBlock);
        XORblocks(currentDataBlock, previousBlk, currentDataBlock);
    }
}

void Cipher::encryptPVS(char*const data, unsigned size) const{
    char* pi = NULL;                                                            // -Will save the binary digits of pi
    char* currentDataBlock = data;
    char _key_[32];                                                             // -Cryptographic key
    std::ifstream file;

    file.open("pi.bin", std::ios::binary);
    if(file.is_open()) {
        UnsignedInt256bits a;                                                   // -Representation of a number of 256 bits (32 bytes)
        UnsignedInt256bits b;                                                   // -Representation of a number of 256 bits (32 bytes)
        _16uint32_64uchar c;                                                    // -Will save the multiplication result
        //unsigned unwrittenSBoxSize = 256;                                       // -We'll rewrite Sbox, this is the size of the entries not substituted yet
        unsigned i, j, k; //l, r;                                                 // -Auxiliary variables
        unsigned _32bytesBlocks = size >> 5;                                    // -Amount of blocks of 64 bytes, _32bytesBlocks = size / 32
        unsigned lastBlockSize = size & 31;                                     // -Size of the last block, lastBlockSize = size % 64
                                                                                // -Using blocks of 64 bytes since the result of the product of two 256 bits number
                                                                                //  is a 512 bits number (size doubles).
        //unsigned char permutationBuffer[256];                                   // -Will be used in the creation of new Sbox
        const char* piIndex;                                                    // -Will go trough the digits of pi

        pi = new char[size];
        file.read(pi, size);                                                    // -Uploading pi
        this->key.write_Key(_key_);
        if(this->key.getLengthBytes() < 32) {
            for(i = this->key.getLengthBytes(), j = 0; i < 32; i++, j++) _key_[i] = _key_[j]; // -Padding with the beginning of the key
        }
        a = UnsignedInt256bits(_key_);                                          // -Creating number from key
        for(i = 0, piIndex = pi; i < _32bytesBlocks; i++, piIndex += 32, currentDataBlock += 32) {
            b.reWriteLeastSignificantBytes(piIndex);                            // -Number from a 32 bytes chunk of pi
            c = a*b;                                                            // -Product with the key
            for(j = 0 ; j < 32; j++) currentDataBlock[j] ^= (char)c.chars[j];
            for(k = 0 ; k < 32; k++,j++) currentDataBlock[k] ^= (char)c.chars[j]; // -Second round of X0R
        }
        if(lastBlockSize > 0) {
            b.reWriteLeastSignificantBytes(piIndex, lastBlockSize);             // -Rewriting with the bytes left
            c = a*b;                                                            // -Product with the key
            for(j = 0 ; j < lastBlockSize; j++) currentDataBlock[j] ^= (char)c.chars[j];
            for(k = 0 ; k < lastBlockSize; k++,j++) currentDataBlock[k] ^= (char)c.chars[j]; // -Second round of X0R
        }
        /*for(i = 0; i < 256; i++ ) permutationBuffer[i] = (unsigned char)i;
        for(i = size-129, j = 0, k = size-1; i < k; i+=32) {                    // -Building Sbox
            b.reWriteLeastSignificantBytes(&pi[i]);                             // -Rewriting with the bytes left
            c = a*b;                                                            // -Product with the key
            for(l = 0; l < 64; l++, j++, unwrittenSBoxSize--) {
                r = c.chars[l] % unwrittenSBoxSize;                             // -Using the number in c as a random number
                this->SBox[j] = permutationBuffer[r];
                permutationBuffer[r] = permutationBuffer[unwrittenSBoxSize - 1];
            }
        }
        for(i = 0; i < 256; i++ ) this->InvSBox[this->SBox[i]] = i;*/             // -Building Sbox inverse
    } else {
        std::cout << "\nCould not open pi.bin file, proceeding with ECB mode\n";
    }
    if(pi != NULL) delete[] pi;
    this->encryptECB(data, size);                                               // -Notice that, if pi.bin file is not found, this operation mode becomes ECB
    this->key.set_OperationMode(Key::PVS);                                      // -Setting operation mode after using ECB encryption function.
}

void Cipher::decryptPVS(char*const data, unsigned size) const{
    char* pi = NULL;                                                            // -Will save the binary digits of pi
    char* currentDataBlock = data;
    char _key_[32];                                                             // -Cryptographic key
    std::ifstream file;

    this->decryptECB(data, size);                                           // -Notice that, if pi.bin file is not found, this operation mode becomes ECB

    file.open("pi.bin", std::ios::binary);
    if(file.is_open()) {
        UnsignedInt256bits a;                                                   // -Representation of a number of 256 bits (32 bytes)
        UnsignedInt256bits b;                                                   // -Representation of a number of 256 bits (32 bytes)
        _16uint32_64uchar c;                                                    // -Will save the multiplication result
        //unsigned unwrittenSBoxSize = 256;                                       // -We'll rewrite Sbox, this is the size of the entries not substituted yet
        unsigned i, j, k;// l, r;
        //unsigned loadedPiSize = (size >> 1) + 32;                             // -Amount of bytes we'll upload from pi.bin file, which is size/2 +32
        unsigned _32bytesBlocks = size >> 5;                                    // -Amount of blocks of 64 bytes, _32bytesBlocks = size / 64
        unsigned lastBlockSize = size & 31;                                     // -Size of the last block, lastBlockSize = size % 64
                                                                                // -Using blocks of 64 bytes since the result of the product of two 256 bits number
                                                                                //  is a 512 bits number (size doubles).
        const char* piIndex;                                                    // -Will go trough the digits of pi
        //unsigned char permutationBuffer[256];                                   // -Will be used in the creation of new Sbox

        pi = new char[size];
        file.read(pi, size);                                                    // -Uploading pi
        /*for(i = 0; i < 256; i++ ) permutationBuffer[i] = (unsigned char)i;
        for(i = size-129, j = 0, k = size-1; i < k; i+=32) {                    // -Building Sbox
            b.reWriteLeastSignificantBytes(&pi[i]);                             // -Rewriting with the bytes left
            c = a*b;                                                            // -Product with the key
            for(l = 0; l < 64; l++, j++, unwrittenSBoxSize--) {
                r = c.chars[l] % unwrittenSBoxSize;                             // -Using the number in c as a random number
                this->SBox[j] = permutationBuffer[r];
                permutationBuffer[r] = permutationBuffer[unwrittenSBoxSize - 1];
            }
        }
        for(i = 0; i < 256; i++ ) this->InvSBox[this->SBox[i]] = i;*/             // -Building Sbox inverse

        //this->decryptECB(data, size);                                           // -Notice that, if pi.bin file is not found, this operation mode becomes ECB

        this->key.write_Key(_key_);
        if(this->key.getLengthBytes() < 32) {
            for(i = this->key.getLengthBytes(), j = 0; i < 32; i++, j++) _key_[i] = _key_[j]; // -Padding with the beginning of the key
        }
        a = UnsignedInt256bits(_key_);                                          // -Creating number from key
        for(i = 0, piIndex = pi; i < _32bytesBlocks; i++, piIndex += 32, currentDataBlock += 32) {
            b.reWriteLeastSignificantBytes(piIndex);                            // -Number from a 32 bytes chunk of pi
            c = a*b;                                                            // -Product with the key
            for(j = 0 ; j < 32; j++) currentDataBlock[j] ^= (char)c.chars[j];
            for(k = 0 ; k < 32; k++,j++) currentDataBlock[k] ^= (char)c.chars[j]; // -Second round of X0R
        }
        if(lastBlockSize > 0) {
            b.reWriteLeastSignificantBytes(piIndex, lastBlockSize);             // -Rewriting with the bytes left
            c = a*b;                                                            // -Product with the key
            for(j = 0 ; j < lastBlockSize; j++) currentDataBlock[j] ^= (char)c.chars[j];
            for(k = 0 ; k < lastBlockSize; k++,j++) currentDataBlock[k] ^= (char)c.chars[j]; // -Second round of X0R
        }
    } else {
        std::cout << "\nCould not open pi.bin file, using ECB decryption mode\n"; // -An exception here could be a better idea
    }
    if(pi != NULL) delete[] pi;
}

void Cipher::decrypt(char*const data, unsigned size) const{
    Key::OperationMode opMode = this->key.getOperationMode();
    std::cout << "\nIn file Source/AES.cpp, function void Cipher::decrypt(char*const data, unsigned size) const. Operation mode = " << opMode << '\n';
    switch(opMode) {
        case Key::ECB:
            this->decryptECB(data, size);
            break;
        case Key::CBC:
            this->decryptCBC(data, size);
            break;
        case Key::CFB:
            break;
        case Key::OFB:
            break;
        case Key::CTR:
            break;
        case Key::PVS:
            this->decryptPVS(data, size);
            break;
    }
}

void Cipher::setIV(char IV[16]) const {                                         // -Naive way of setting the initial vector.
    intToChar ic;
    ic.integer = time(NULL);
    int i, j, k;
    for(i = 0; i < 4; i++, ic.integer++) {
        k = i << 2;                                                             // -k = i * 4
        for(j = 0; j < 4; j++) IV[k + j] = ic.chars[j];
    }
    encryptBlock(IV);
}

void Cipher::XORblocks(char b1[16], char b2[16], char r[16]) const {
    for(int i = 0; i < 16; i++) r[i] = b1[i] ^ b2[i];
}

void Cipher::printState(const char state[16]) {
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

void Cipher::CopyWord(const char source[4], char destination[4]) const {
    for(int i = 0; i < 4; i++) destination[i] = source[i];
}

void Cipher::CopyBlock(const char source[16], char destination[16]) const {
    for(int i = 0; i < 16; i++) destination[i] = source[i];
}

void Cipher::XORword(const char w1[4], const char w2[4], char resDest[4]) const{
    for(int i = 0; i < 4; i++) resDest[i] = w1[i] ^ w2[i];
}

void Cipher::RotWord(char word[4]) const{
    char temp = word[0]; int i;
	for(i = 0; i < 3; i++) word[i] = word[i + 1];
	word[3] = temp;
}

void Cipher::SubWord(char word[4]) const{
    for(int i = 0; i < 4; i++) word[i] = (char)SBox[(ui08)word[i]];
}

void Cipher::SubBytes(char state[16]) const{                                    // -Applies a substitution table (S-box) to each char.
	for(int i = 0; i < 16; i++) state[i] = (char)SBox[(ui08)state[i]];
}

void Cipher::ShiftRows(char state[16]) const{                                   // -Shift rows of the state array by different offset.
	int i, j; char tmp[4];
	for(i = 1; i < 4; i++) {
		for(j = 0; j < 4; j++) tmp[j] = state[i + (j << 2)];
		for(j = 0; j < 4; j++) state[i + (j << 2)] = tmp[(j + i) & 3];
	}
}

void Cipher::MixColumns(char state[16]) const{                                  // -Mixes the data within each column of the state array.
    int i, I, j, k;
	char temp[4];
	for(i = 0; i < 4; i++) {
	    I = i << 2;                                                             // I = i * 4;
		for(k = 0; k < 4; k++) temp[k] = state[I + k];                          // Copying row.
		for(j = 0; j < 4; j++) {
			state[I + j] = (char)multiply[ (int)(ui08)a[(4 - j) & 3] ][ (int)(ui08)temp[0] ]; // -First state column element times matrix first column
			for(k = 1; k < 4; k++) {
				state[I + j] ^= (char)multiply[ (int)(ui08)a[(k - j + 4)&3] ][ (int)(ui08)temp[k] ];
			}
		}
	}
}

void Cipher::AddRoundKey(char state[16], int round) const{                      // -Combines a round key with the state.
    round <<= 4;                                                                // -Each round uses 16 bytes and r <<= 4 == r *= 16.
	for(int i = 0; i < 16; i++) state[i] ^= keyExpansion[round + i];
}

void Cipher::encryptBlock(char block[]) const {
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

void Cipher::InvSubBytes(char state[16]) const{
    for(int i = 0; i < 16; i++) state[i] = (char)InvSBox[(ui08)state[i]];
}

void Cipher::InvShiftRows(char state[16]) const{
    int i, j; char temp[4];
	for(i = 1; i < 4; i++) {
		for(j = 0; j < 4; j++) temp[j] = state[i + (j << 2)];
		for(j = 0; j < 4; j++) state[(j << 2) + i] = temp[(j - i + 4) & 3];
	}
}

void Cipher::InvMixColumns(char state[16]) const{
    int  i, j, k, I;
	char temp[4];
	for(i = 0; i < 4; i ++) {
	    I = i << 2;                                                             // -I = i * 4
		for(j = 0; j < 4; j++) temp[j] = state[I + j];
		for(j = 0; j < 4; j++) {
			state[I + j] = (char)multiply[ (int)(ui08)aInv[(4 - j) & 0x03] ][ (int)(ui08)temp[0] ];
			for(k = 1; k < 4; k++)
			    state[I + j] ^= (char)multiply[ (int)(ui08)aInv[(k - j + 4)&3] ][ (int)(ui08)temp[k] ];
		}
	}
}

void Cipher::decryptBlock(char block[16]) const {
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
