#include<fstream>
#include<cstring>
#include<random>
#include<exception>
#include"../../include/AESencryption.hpp"

#define MAX_KEY_LENGTH_BYTES 32

using namespace AESencryption;

/*********************************************************************** Helper functions ************************************************************************/

static void OpModeToString(Key::OpMode opm, char*const destination) {  // -Assuming destination is a pointer to an array of at least four elements.
    switch(opm) {
        case Key::OpMode::ECB: strcpy(destination, "ECB");
            break;
        case Key::OpMode::CBC: strcpy(destination, "CBC");
            break;
    }
}

static int bytesToHexString(const uint8_t*const origin, char*const destination, const int len) { // -From an array of bytes creates a string witch is the
    if(len <= 0) return -1;                                                     //  representation in hexadecimal of that byte array
    char buff;                                                                  // -The resulting string is written on the "destination" pointer. We assume this
    int  i, j;
    for(i = 0, j = 0; i < len; i++) {                                           //  pointer points to an array with lenBits at least 2*len+1
        buff = (char)origin[i] >> 4;                                            // -Taking the four most significant bits
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
    this->key = new uint8_t[this->lenBytes];
    for(size_t i = 0; i < this->lenBytes; i++) this->key[i] = 0;
}

Key::Key(Len len, OpMode op_m): lenBits(len), lenBytes((size_t)len >> 3), opMode_(op_m){
    std::random_device dev; std::mt19937 seed(dev());
    std::uniform_int_distribution<std::mt19937::result_type> distribution;      // -Random number with uniform distribution
    size_t i;
    union { int integer; char chars[4]; } buff;                              // -Anonymous union. Casting from 32 bits integer to four chars
    this->key = new uint8_t[this->lenBytes];
    for(i = 0; i < this->lenBytes; i += 4) {                                    // -I am supposing everything is fine and lenBytes is a multiple of four
        buff.integer = distribution(seed);                                      // -Taking a random 32 bits integer to divide it into four bytes
        memcpy((char*)(this->key + i), buff.chars, 4);
    }
}

Key::Key(const uint8_t* const _key, Len len, OpMode op_m): lenBits(len), lenBytes((size_t)len >> 3), opMode_(op_m){
    this->key = new uint8_t[this->lenBytes];
    if(_key != NULL) for(size_t i = 0; i < this->lenBytes; i++) this->key[i] = _key[i];
}

Key::Key(const Key& ak):lenBits(ak.lenBits), lenBytes(ak.lenBytes), opMode_(ak.opMode_) {
    size_t i;
    this->key = new uint8_t[ak.lenBytes];
    for(i = 0; i < ak.lenBytes; i++) this->key[i] = ak.key[i];               // -Supposing Cipher object is well constructed, this is, ak.key != NULL
    if(ak.opMode_ == OpMode::CBC) {                                              // -Without CBC, copying IV is pointless.
        if((this->initializedIV = ak.initializedIV) == true)                    // -Copying and checking argument inside the 'if'
            for(i = 0; i < BLOCK_SIZE; i++) this->IV[i] = ak.IV[i];
    }
}

Key::Key(const uint8_t*const fname) : lenBits(Len::_128), lenBytes(BLOCK_SIZE), opMode_(OpMode::ECB) { // -Building from .key file
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

                this->key = new uint8_t[this->lenBytes];                        // -Reading key
                file.read((char*)this->key, (std::streamsize)this->lenBytes);

                if(this->opMode_ == OpMode::CBC) {
                    file.read((char*)(this->key.IV.data), BLOCK_SIZE);                     // -In CBC case, reading IV.
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
            this->key = new uint8_t[k.lenBytes];
        }
        for(i = 0; i < k.lenBytes; i++) this->key[i] = k.key[i];
        this->opMode_ = k.opMode_;
        if(k.opMode_ == OpMode::CBC)                                             // -Without CBC, copying IV is pointless.
            if((this->initializedIV = k.initializedIV) == true)
                for(i = 0; i < BLOCK_SIZE; i++) this->IV[i] = k.IV[i];
    }
    return *this;
}

bool Key::operator == (const Key& k) const{
    unsigned i;
    if(this->lenBytes != k.lenBytes) return false;
    for(i = 0; i < this->lenBytes; i++) if(this->key[i] != k.key[i]) return false;
    if(this->opMode_ == k.opMode_) {
        if(this->opMode_ == OpMode::CBC)
            for(i = 0; i < BLOCK_SIZE; i++) if(this->IV[i] != k.IV[i]) return false;
    } else return false;
    return true;
}

std::ostream& AESencryption::operator << (std::ostream& ost, Key k) {
    char keyStr[65];
    char opModeStr[4];
    char IVstring[33];

    OpModeToString(k.opMode_, opModeStr);
    bytesToHexString(k.key, keyStr, (int)k.lenBytes);
    bytesToHexString(k.IV, IVstring, BLOCK_SIZE);

    ost << "\tKey size: " << static_cast<int>(k.lenBits) << " bits, " << k.lenBytes << " bytes, Nk = " << (k.lenBytes >> 2) << " words" << '\n';
    ost << "\tKey: " << keyStr << '\n';
    ost << "\tOperation mode: " << opModeStr << '\n';
    ost << "\tIV (in case of CBC): "<< IVstring << '\n';

    return ost;
}

void Key::set_IV(const InitVector source) {
    if(!this->initializedIV) for(int i = 0; i < BLOCK_SIZE; i++) this->IV.data[i] = source.data[i];
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
        if(this->opMode_ == OpMode::CBC) file.write(this->IV, BLOCK_SIZE);       // -If CBC, writes initial vector
    } else {
        std::cerr << "In file Source/AES.cpp, function void Key::save(const char* const fname): Failed to write " << fname << " file.\n";
        throw std::runtime_error("File could not be written.");
    }
}
