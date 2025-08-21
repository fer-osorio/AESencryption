#include"../../include/AESencryption.hpp"
#include"../AES/AES.h"
#include"../operation_modes/operation_modes.h"

using namespace AESencryption;

Cipher::Cipher() {
    this->keyExpansion = new uint8_t[this->keyExpLen];
    for(int i = 0; i < this->keyExpLen; i++) this->keyExpansion[i] = 0;         // -Since the key constitutes of just zeros, key expansion is also just zeros
}

Cipher::Cipher(const Key& ak) :key(ak), Nk((int)ak.getLenBytes() >> 2), Nr(Nk+6), keyExpLen((Nr+1)<<4) {
    this->create_KeyExpansion(ak.key);
}

Cipher::Cipher(const Cipher& a) : key(a.key), Nk(a.Nk), Nr(a.Nr), keyExpLen(a.keyExpLen) {
    this->keyExpansion = new uint8_t[(unsigned)a.keyExpLen];
    for(int i = 0; i < a.keyExpLen; i++) this->keyExpansion[i] = a.keyExpansion[i];
}

Cipher::~Cipher() {
    if(keyExpansion != NULL) delete[] keyExpansion;
    keyExpansion = NULL;
}

Cipher& Cipher::operator = (const Cipher& a) {
    if(this != &a) {
        this->key = a.key;
        if(this->keyExpLen != a.keyExpLen) {
            this->Nk = a.Nk;
            this->Nr = a.Nr;
            this->keyExpLen = a.keyExpLen;
            if(this->keyExpansion != NULL) delete[] keyExpansion;
            this->keyExpansion = new uint8_t[(unsigned)a.keyExpLen];
        }
        for(int i = 0; i < a.keyExpLen; i++) this->keyExpansion[i] = a.keyExpansion[i];
    }
    return *this;
}

/*std::ostream& AESencryption::operator << (std::ostream& ost, const Cipher& c) {
    char keyExpansionString[880];
    int rowsAmount = c.keyExpLen >> 5;                                          // -rowsAmount = c.keyExpLen / 32
    int i, j, k, l;
    for(i = 0, j = 0, k = 0; i < rowsAmount; i++, j+=32, k+=64) {               // -Rows with 32 columns
        keyExpansionString[k++] = '\n';
        keyExpansionString[k++] = '\t';
        keyExpansionString[k++] = '\t';
        bytesToHexString(&c.keyExpansion[j], &keyExpansionString[k], 32);       // -Writing 32 bites pointed by &c.keyExpansion[j] in hexadecimal over 65 chars
    }                                                                           //  over &keyExpansionString[k]
    if((l = c.keyExpLen & 31) > 0) {                                            // -l = c.keyExpLen % 31
        keyExpansionString[k++] = '\n';
        keyExpansionString[k++] = '\t';
        keyExpansionString[k++] = '\t';
        bytesToHexString(&c.keyExpansion[j], &keyExpansionString[k], l);
        keyExpansionString[k+(l<<1)] = 0;                                       // -k+(l<<1) = k + l*2
    }
    else keyExpansionString[k] = 0;
    ost << "AES::Cipher object information:\n";
    ost << c.key;
    ost << "\tNr: " << c.Nr << " rounds" << '\n';
    ost << "\tKey Expansion size: " << c.keyExpLen << " bytes" << '\n';
    ost << "\tKey Expansion: " << keyExpansionString << '\n';
    return ost;
}*/

void Cipher::create_KeyExpansion(const uint8_t* const _key) {
}

void Cipher::encryptECB(uint8_t*const data, size_t size) const{
    if(size == 0)    return;
    if(data == NULL) return;

    char* currentDataBlock = data;
    int numofBlocks = int(size >> 4);                                           //  numofBlocks = size / 16.
    int rem = int(size & 15), i;                                                // -Bytes remaining rem = size % 16

    --numofBlocks;                                                              // Last block will be treated differently.
    for(i = 0; i < numofBlocks; i++) {
        encryptBlock(currentDataBlock);
        currentDataBlock += AES_BLK_SZ;
    }
    if(rem != 0) {                                                              // -This part of the code is for encrypt data that its size is not multiple of 16.
        encryptBlock(currentDataBlock);                                         //  This is not specified in the NIST standard.
        encryptBlock(currentDataBlock + rem);                                   // -Not handling the case size < 16
        return;
    }
    encryptBlock(currentDataBlock);
}

void Cipher::decryptECB(char *const data, size_t size) const{
    if(size == 0)    return;
    if(data == NULL) return;

    char* currentDataBlock = data;
    int numofBlocks = int(size >> 4);                                           //  numofBlocks = size / 16.
    int rem = int(size & 15), i;                                                // -Bytes remaining rem = size % 16

    --numofBlocks;                                                              // Last block will be treated differently.
    for(i = 0; i < numofBlocks; i++) {
        decryptBlock(currentDataBlock);
        currentDataBlock += AES_BLK_SZ;
    }
    if(rem != 0) {                                                              // -This part of the code is for encrypt data that its size is not multiple of 16.
        decryptBlock(currentDataBlock + rem);                                   //  This is not specified in the NIST standard.
        decryptBlock(currentDataBlock);                                         // -Not handling the case size < 16
        return;
    }
    decryptBlock(currentDataBlock);
}

void Cipher::setAndWrite_IV(char destination[AES_BLK_SZ]) const{                // -Simple method for setting the initial vector. The main idea is, when CBC is
    int_char ic; ic.int_ = time(NULL);                                         //  used, encryptBlock function encrypts a block of four consecutive 32 bits int's
    int icIntWordSize = sizeof(ic.int_);                                        // -At this moment, this is suppose to be equal to 4
    int j, k;
    for(k = 0; k < AES_BLK_SZ; ic.int_++)
        for(j = 0; j < icIntWordSize && k < AES_BLK_SZ; j++) destination[k++] = ic.chars[j];
    this->encryptBlock(destination);
}

void Cipher::encryptCBC(char*const data, size_t size) const{
    if(size == 0)    return;
    if(data == NULL) return;

    char *previousBlk, *currentDataBlock = data;
    char IVsource[AES_BLK_SZ];
    int numofBlocks = (int)size >> 4;                                           //  numofBlocks = size / 16.
    int rem = (int)size & 15, i;                                                // -Bytes remaining rem = size % 16

    this->key.write_IV(IVsource);
    XORblocks(currentDataBlock, IVsource, currentDataBlock);                    // -Encryption of the first block.
    encryptBlock(currentDataBlock);

    for(i = 1; i < numofBlocks; i++) {                                          // -Encryption of the rest of the blocks.
        previousBlk = currentDataBlock;
        currentDataBlock += AES_BLK_SZ;
        XORblocks(currentDataBlock, previousBlk, currentDataBlock);
        encryptBlock(currentDataBlock);
    }
    if(rem != 0) {                                                              // -This part of the code is for encrypt data that its size is not multiple of 16.
        previousBlk = currentDataBlock;                                         //  This is not specified in the NIST standard.
        currentDataBlock += AES_BLK_SZ;
        for(i=0; i<rem; i++) currentDataBlock[i] = currentDataBlock[i] ^ previousBlk[i];
        encryptBlock(previousBlk + rem);
    }
}


void Cipher::decryptCBC(char*const data, size_t size) const{
    if(size == 0)    return;
    if(data == NULL) return;

    char *currentDataBlock = data, previousBlk[AES_BLK_SZ], cipherCopy[AES_BLK_SZ];
    int numofBlocks = (int)size >> 4;                                           // -numofBlocks = size / 16
    int rem = (int)size & 15;                                                   // -Rest of the bytes rem = size % 16
    int i;

    this->key.write_IV(cipherCopy);
    CopyBlock(currentDataBlock, previousBlk);                                   // -Copying the first ciphered block.

    decryptBlock(currentDataBlock);                                             // -Deciphering the first block.
    XORblocks(currentDataBlock, cipherCopy, currentDataBlock);

    if(numofBlocks > 0) numofBlocks--;                                          // -Last block is going to be processed differently.
    for(i = 1; i < numofBlocks; i++) {                                          // -Decryption of the rest of the blocks.
        currentDataBlock += AES_BLK_SZ;
        CopyBlock(currentDataBlock, cipherCopy);                                // -Saving cipher block for the next round.
        decryptBlock(currentDataBlock);
        XORblocks(currentDataBlock, previousBlk, currentDataBlock);
        CopyBlock(cipherCopy, previousBlk);                                     // -Cipher block now becomes previous block.
    }
    currentDataBlock += AES_BLK_SZ;
    if(rem == 0) {                                                              // -Data size is a multiple of 16.
        decryptBlock(currentDataBlock);
        XORblocks(currentDataBlock, previousBlk, currentDataBlock);
    } else {                                                                    // -Data size isn't a multiple of 16.
        decryptBlock(currentDataBlock + rem);
        for(i = 0; i < rem; i++)
            currentDataBlock[i+AES_BLK_SZ] = currentDataBlock[i+AES_BLK_SZ] ^ currentDataBlock[i];
        decryptBlock(currentDataBlock);
        XORblocks(currentDataBlock, previousBlk, currentDataBlock);
    }
}

void Cipher::encrypt(char*const data, size_t size) const{
    if(size == 0)    return;
    if(data == NULL) return;
    Key::OpMode opMode = this->key.getOpMode();
    switch(opMode) {
        case Key::OpMode::ECB:
            this->encryptECB(data, size);
            break;
        case Key::OpMode::CBC:
            this->encryptCBC(data, size);
            break;
    }
}

void Cipher::decrypt(char*const data, size_t size) const{
    if(size == 0)    return;
    if(data == NULL) return;
    Key::OpMode opMode = this->key.getOpMode();
    switch(opMode) {
        case Key::OpMode::ECB:
            this->decryptECB(data, size);
            break;
        case Key::OpMode::CBC:
            this->decryptCBC(data, size);
            break;
    }
}
