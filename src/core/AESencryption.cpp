#include<fstream>
#include<cstring>
#include<random>
#include<exception>
#include"../../include/AES.hpp"

#define MAX_KEY_LENGTH_BYTES 32

using namespace AES;

/*********************************************************************** Helper functions ************************************************************************/

static void OpModeToString(Key::OpMode opm, char*const destination) {  // -Assuming destination is a pointer to an array of at least four elements.
    switch(opm) {
        case Key::OpMode::ECB: strcpy(destination, "ECB");
            break;
        case Key::OpMode::CBC: strcpy(destination, "CBC");
            break;
    }
}

static int bytesToHexString(const char*const origin, char*const destination, const int len) { // -From an array of bytes creates a string witch is the
    if(len <= 0) return -1;                                                     //  representation in hexadecimal of that byte array
    char buff;                                                                  // -The resulting string is written on the "destination" pointer. We assume this
    int  i, j;
    for(i = 0, j = 0; i < len; i++) {                                           //  pointer points to an array with lenBits at least 2*len+1
        buff = (char)((uint8_t)origin[i] >> 4);                                 // -Taking the four most significant bits
        if(buff<10) destination[j++] = buff + 48;                               // -To hexadecimal digit
        else        destination[j++] = buff + 55;                               //  ...
        buff = origin[i] & 15;                                                  // -Taking the four least significant byte
        if(buff<10) destination[j++] = buff + 48;                               // -To hexadecimal digit
        else        destination[j++] = buff + 55;                               //  ...
    }
    destination[j] = 0;                                                         // -End of string
    return 0;
}

/************************************************************** Handling AES cryptographic keys ******************************************************************/

Key::Key(): lenBits(Len::_256), lenBytes(32), opMode_(OpMode::CBC) {
    this->key = new char[this->lenBytes];
    for(size_t i = 0; i < this->lenBytes; i++) this->key[i] = 0;
}

Key::Key(Len len, OpMode op_m): lenBits(len), lenBytes((size_t)len >> 3), opMode_(op_m){
    std::random_device dev; std::mt19937 seed(dev());
    std::uniform_int_distribution<std::mt19937::result_type> distribution;      // -Random number with uniform distribution
    size_t i;
    union { int integer; char chars[4]; } buff;                                 // -Anonymous union. Casting from 32 bits integer to four chars
    this->key = new char[this->lenBytes];
    for(i = 0; i < this->lenBytes; i += 4) {                                 // -I am supposing everything is fine and lenBytes is a multiple of four
        buff.integer = distribution(seed);                                      // -Taking a random 32 bits integer to divide it into four bytes
        memcpy((char*)(this->key + i), buff.chars, 4);
    }
}

Key::Key(const char* const _key, Len len, OpMode op_m): lenBits(len), lenBytes((size_t)len >> 3), opMode_(op_m){
    this->key = new char[this->lenBytes];
    if(_key != NULL) for(size_t i = 0; i < this->lenBytes; i++) this->key[i] = _key[i];
}

Key::Key(const Key& ak):lenBits(ak.lenBits), lenBytes(ak.lenBytes), opMode_(ak.opMode_) {
    size_t i;
    this->key = new char[ak.lenBytes];
    for(i = 0; i < ak.lenBytes; i++) this->key[i] = ak.key[i];               // -Supposing Cipher object is well constructed, this is, ak.key != NULL
    if(ak.opMode_ == OpMode::CBC) {                                              // -Without CBC, copying IV is pointless.
        if((this->initializedIV = ak.initializedIV) == true)                    // -Copying and checking argument inside the 'if'
            for(i = 0; i < AES_BLK_SZ; i++) this->IV[i] = ak.IV[i];
    }
}

Key::Key(const char*const fname):lenBits(Len::_128), lenBytes(AES_BLK_SZ), opMode_(OpMode::ECB) { // -Building from .key file
    char aeskeyStr[] = "AESKEY";
    char AESKEY[7];
    char opMode[4];
    uint16_t keyLen;
    size_t len_aeskeyStr = strlen(aeskeyStr);
    std::ifstream file;
    file.open(fname, std::ios::binary);
    if(file.is_open()) {
        file.read((char*)AESKEY, (std::streamsize)len_aeskeyStr);               // -Determining if file is a .key file
        AESKEY[6] = 0;                                                          // -End of string
        if(strcmp(AESKEY, aeskeyStr) == 0) {
                file.read((char*)opMode, 3);                                    // -Determining operation mode
                opMode[3] = 0;
                if(strcmp(opMode, "ECB") == 0) this->opMode_ = OpMode::ECB;
                else if(strcmp(opMode, "CBC") == 0) this->opMode_ = OpMode::CBC;
                else {
                    std::cerr << "In file Source/AES.cpp, function Key::Key(const char*const fname):" << opMode << ", not a recognized operation mode.\n";
                    throw std::runtime_error("Not a recognized operation mode");
                }

                file.read((char*)&keyLen, 2);                                      // -Reading key lenBits
                if(keyLen == 128 || keyLen == 192 || keyLen == 256) this->lenBits = (Len)keyLen;
                else {
                    std::cerr << "In file Source/AES.cpp, function Key::Key(const char*const fname):" << keyLen << " is not a valid length in bits for key.\n";
                    throw std::runtime_error("Key length not allowed.");
                }
                this->lenBytes = keyLen >> 3;                                // -lenBytes = len / 8;

                this->key = new char[this->lenBytes];                        // -Reading key
                file.read(this->key, (std::streamsize)this->lenBytes);

                if(this->opMode_ == OpMode::CBC) {
                    file.read((char*)this->IV, AES_BLK_SZ);                     // -In CBC case, reading IV.
                    this->initializedIV = true;
                }
           } else {
                std::cerr << "In file Source/AES.cpp, function Key::Key(const char*const fname): String " << fname << " does not represent a valid AES key file.\n";
                throw std::runtime_error("Not a valid AES key file.");
           }
    } else {
        std::cerr << "In file Source/AES.cpp, function Key::Key(const char*const fname): Failed to open " << fname << " file.\n";
        throw std::runtime_error("Could not open file.");
    }
}

Key::~Key() {
    if(this->key != NULL) delete[] this->key;
    this->key = NULL;
}

Key& Key::operator = (const Key& k) {
    if(this != &k) {                                                            // -Guarding against self assignment
        unsigned i;
        if(this->lenBytes != k.lenBytes) {                                // -Modifying length and array containing key only if necessary
            this->lenBits = k.lenBits;
            this->lenBytes = k.lenBytes;
            if(this->key != NULL) delete[] this->key;
            this->key = new char[k.lenBytes];
        }
        for(i = 0; i < k.lenBytes; i++) this->key[i] = k.key[i];
        this->opMode_ = k.opMode_;
        if(k.opMode_ == OpMode::CBC)                                             // -Without CBC, copying IV is pointless.
            if((this->initializedIV = k.initializedIV) == true)
                for(i = 0; i < AES_BLK_SZ; i++) this->IV[i] = k.IV[i];
    }
    return *this;
}

bool Key::operator == (const Key& k) const{
    unsigned i;
    if(this->lenBytes != k.lenBytes) return false;
    for(i = 0; i < this->lenBytes; i++) if(this->key[i] != k.key[i]) return false;
    if(this->opMode_ == k.opMode_) {
        if(this->opMode_ == OpMode::CBC)
            for(i = 0; i < AES_BLK_SZ; i++) if(this->IV[i] != k.IV[i]) return false;
    } else return false;
    return true;
}

std::ostream& AES::operator << (std::ostream& ost, Key k) {
    char keyStr[65];
    char opModeStr[4];
    char IVstring[33];

    OpModeToString(k.opMode_, opModeStr);
    bytesToHexString(k.key, keyStr, (int)k.lenBytes);
    bytesToHexString(k.IV, IVstring, AES_BLK_SZ);

    ost << "\tKey size: " << static_cast<int>(k.lenBits) << " bits, " << k.lenBytes << " bytes, Nk = " << (k.lenBytes >> 2) << " words" << '\n';
    ost << "\tKey: " << keyStr << '\n';
    ost << "\tOperation mode: " << opModeStr << '\n';
    ost << "\tIV (in case of CBC): "<< IVstring << '\n';

    return ost;
}

void Key::set_IV(const char source[AES_BLK_SZ]) {
    if(!this->initializedIV) for(int i = 0; i < AES_BLK_SZ; i++) this->IV[i] = source[i];
    this->initializedIV = true;
}

void Key::save(const char* const fname) const {
    const char* aeskey = "AESKEY";                                              // File type.
    const char* op_mode= "ECB";
    switch(this->opMode_) {                                              // -Operation mode.
        case OpMode::ECB:
            op_mode = "ECB";
            break;
        case OpMode::CBC:
            op_mode = "CBC";
            break;
    }
    std::ofstream file;
    file.open(fname, std::ios::binary);
    if(file.is_open()) {
        file.write(aeskey,  6);                                                 // -File type
        file.write(op_mode, 3);                                                 // -Operation mode
        file.write((char*)&this->lenBits, 2);                                // -Key lenBits in bits
        file.write(this->key, (std::streamsize)this->lenBytes);              // -Key
        if(this->opMode_ == OpMode::CBC) file.write(this->IV, AES_BLK_SZ);       // -If CBC, writes initial vector
    } else {
        std::cerr << "In file Source/AES.cpp, function void Key::save(const char* const fname): Failed to write " << fname << " file.\n";
        throw std::runtime_error("File could not be written.");
    }
}


/************************************************** AES encryption and decryption algorithms implementation ******************************************************/


Cipher::Cipher(): {
    this->keyExpansion = new char[this->keyExpLen];
    for(int i = 0; i < this->keyExpLen; i++) this->keyExpansion[i] = 0;         // -Since the key constitutes of just zeros, key expansion is also just zeros
}

Cipher::Cipher(const Key& ak) :key(ak), Nk((int)ak.getLenBytes() >> 2), Nr(Nk+6), keyExpLen((Nr+1)<<4) {
    this->create_KeyExpansion(ak.key);
    if(this->key.opMode_ == Key::OpMode::CBC) {
        if(!this->key.IVisInitialized()) {                                      // -In case of CBC, setting initial vector.
            char IVsource[AES_BLK_SZ];
            this->setAndWrite_IV(IVsource);
            this->key.set_IV(IVsource);
        }
    }
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
        if(this->keyExpLen != a.keyExpLen) {
            this->Nk = a.Nk;
            this->Nr = a.Nr;
            this->keyExpLen = a.keyExpLen;
            if(this->keyExpansion != NULL) delete[] keyExpansion;
            this->keyExpansion = new char[(unsigned)a.keyExpLen];
        }
        for(int i = 0; i < a.keyExpLen; i++) this->keyExpansion[i] = a.keyExpansion[i];
    }
    return *this;
}

std::ostream& AES::operator << (std::ostream& ost, const Cipher& c) {
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
}

void Cipher::create_KeyExpansion(const char* const _key) {
}

void Cipher::encryptECB(char*const data, size_t size) const{
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
