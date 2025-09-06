#include<fstream>
#include<cstring>
#include<random>
#include<exception>
#include"../../include/key.hpp"
#include"../utils/include/print_bytes.hpp"

using namespace AESencryption;

static size_t fromLenBitsToLenBytes(Key::LenBits lenbits){
    return size_t(lenbits)/8;
}

Key::Key()
    : lenBits(LenBits::_256), lenBytes(fromLenBitsToLenBytes(lenBits)), opMode_(OpMode::ECB) {
    this->data = new uint8_t[this->lenBytes];
    for(size_t i = 0; i < this->lenBytes; i++) this->data[i] = 0;
}

Key::Key(LenBits lenbits, OpMode op_m)
    : lenBits(lenbits), lenBytes(fromLenBitsToLenBytes(lenbits)), opMode_(op_m){
    std::random_device dev; std::mt19937 seed(dev());
    std::uniform_int_distribution<std::mt19937::result_type> distribution;      // -Random number with uniform distribution
    size_t i;
    union { int integer; char chars[4]; } buff;                                 // -Anonymous union. Casting from 32 bits integer to four chars
    this->data = new uint8_t[this->lenBytes];
    for(i = 0; i < this->lenBytes; i += 4) {                                    // -I am supposing everything is fine and lenBytes is a multiple of four
        buff.integer = distribution(seed);                                      // -Taking a random 32 bits integer to divide it into four bytes
        memcpy((char*)(this->data + i), buff.chars, 4);
    }
}

Key::Key(const uint8_t* const _key, LenBits lenbits, OpMode op_m)
    : lenBits(lenbits), lenBytes(fromLenBitsToLenBytes(lenbits)), opMode_(op_m){
    this->data = new uint8_t[this->lenBytes];
    if(_key != NULL) for(size_t i = 0; i < this->lenBytes; i++) this->data[i] = _key[i];
}

Key::Key(const Key& k)
    :lenBits(k.lenBits), lenBytes(k.lenBytes), opMode_(k.opMode_) {
    size_t i;
    this->data = new uint8_t[k.lenBytes];
    for(i = 0; i < k.lenBytes; i++) this->data[i] = k.data[i];                  // -Supposing Cipher object is well constructed, this is, k.data != NULL
    if(k.opMode_ == OpMode::CBC) {                                              // -Without CBC, copying IV is pointless.
        for(i = 0; i < AESconstants::BLOCK_SIZE; i++) this->IV.data[i] = k.IV.data[i];
    }
}

Key::Key(const char*const fname)
    : lenBits(LenBits::_128), lenBytes(AESconstants::BLOCK_SIZE), opMode_(OpMode::ECB) {
    char aeskeyStr[] = "AESKEY";
    char AESKEY[7];
    char opMode[4];
    uint16_t keyLen;
    size_t len_aeskeyStr = strlen(aeskeyStr);
    std::ifstream file;
    file.open(fname, std::ios::binary);
    if(file.is_open()) {
        file.read((char*)AESKEY, (std::streamsize)len_aeskeyStr);               // -Determining if file is a .data file
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
                file.read((char*)&keyLen, 2);                                   // -Reading key lenBits
                if(keyLen == uint16_t(LenBits::_128) || keyLen == uint16_t(LenBits::_192) || keyLen == uint16_t(LenBits::_256))
                    this->lenBits = (LenBits)keyLen;
                else {
                    std::cerr << "In file Source/AES.cpp, function Key::Key(const char*const fname):" << keyLen << " is not a valid length in bits for key.\n";
                    throw std::runtime_error("Key length not allowed.");
                }
                this->lenBytes = fromLenBitsToLenBytes(this->lenBits);          // -lenBytes = lenbits / 8;
                this->data = new uint8_t[this->lenBytes];                       // -Reading key
                file.read((char*)this->data, (std::streamsize)this->lenBytes);
                if(this->opMode_ == OpMode::CBC) {
                    file.read((char*)(this->IV.data), AESconstants::BLOCK_SIZE);              // -In CBC case, reading IV.
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
    if(this->data != NULL) delete[] this->data;
    this->data = NULL;
}

Key& Key::operator = (const Key& k) {
    if(this != &k) {                                                            // -Guarding against self assignment
        unsigned i;
        if(this->lenBytes != k.lenBytes) {                                // -Modifying length and array containing key only if necessary
            this->lenBits = k.lenBits;
            this->lenBytes = k.lenBytes;
            if(this->data != NULL) delete[] this->data;
            this->data = new uint8_t[k.lenBytes];
        }
        for(i = 0; i < k.lenBytes; i++) this->data[i] = k.data[i];
        this->opMode_ = k.opMode_;
        if(k.opMode_ == OpMode::CBC)                                             // -Without CBC, copying IV is pointless.
            if((this->initializedIV = k.initializedIV) == true)
                for(i = 0; i < AESconstants::BLOCK_SIZE; i++) this->IV.data[i] = k.IV.data[i];
    }
    return *this;
}

bool Key::operator == (const Key& k) const{
    unsigned i;
    if(this->lenBytes != k.lenBytes) return false;
    for(i = 0; i < this->lenBytes; i++) if(this->data[i] != k.data[i]) return false;
    if(this->opMode_ == k.opMode_) {
        if(this->opMode_ == OpMode::CBC)
            for(i = 0; i < AESconstants::BLOCK_SIZE; i++) if(this->IV.data[i] != k.IV.data[i]) return false;
    } else return false;
    return true;
}

static const char* opModeToString(Key::OpMode mode) {
    switch (mode) {
        case Key::OpMode::ECB: return "ECB";
        case Key::OpMode::CBC: return "CBC";
        default: return "Unknown";
    }
}

std::ostream& AESencryption::operator<<(std::ostream& ost, const Key& k) {
    ost << "\tKey size: " << static_cast<int>(k.lenBits) << " bits, " << k.lenBytes << " bytes, Nk = " << (k.lenBytes >> 2) << " words\n";
    ost << "\tKey: ";
    print_bytes_as_hex(ost, k.data, k.lenBytes);
    ost << '\n';
    ost << "\tOperation mode: " << opModeToString(k.opMode_) << '\n';
    if (k.opMode_ == Key::OpMode::CBC && k.initializedIV) {                     // Only print the IV if the mode is CBC and the IV is initialized
        ost << "\tIV (for CBC): ";
        print_bytes_as_hex(ost, k.IV.data, 16); // IV is typically 16 bytes for AES
        ost << '\n';
    }
    return ost;
}

void Key::set_IV(const InitVector source) {
    if(!this->initializedIV)
        for(int i = 0; i < AESconstants::BLOCK_SIZE; i++)
            this->IV.data[i] = source.data[i];
    this->initializedIV = true;
}

void Key::save(const char*const fname) const {
    const char* aeskey = "AESKEY";                                              // File type.
    const char* op_mode= "ECB";
    switch(this->opMode_) {                                                     // -Operation mode.
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
        file.write((char*)&this->lenBits, 2);                                   // -Key lenBits in bits
        file.write((char*)this->data, (std::streamsize)this->lenBytes);         // -Key
        if(this->opMode_ == OpMode::CBC) file.write((char*)this->IV.data, AESconstants::BLOCK_SIZE); // -If CBC, writes initial vector
    } else {
        std::cerr << "In file Source/AES.cpp, function void Key::save(const char* const fname): Failed to write " << fname << " file.\n";
        throw std::runtime_error("File could not be written.");
    }
}
