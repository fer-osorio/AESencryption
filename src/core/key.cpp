#include<fstream>
#include<string>
#include<cstring>
#include<random>
#include"../../data-encryption/include/constants.h"
#include"../../include/key.hpp"
#include"../utils/print_bytes.hpp"

using namespace AESencryption;

static size_t fromLenBitsToLenBytes(Key::LengthBits lenbits){
    return size_t(lenbits)/8;
}

Key::Key(): lenBits(LengthBits::_256), lenBytes(fromLenBitsToLenBytes(lenBits)) {
    this->data = new uint8_t[this->lenBytes];
    for(size_t i = 0; i < this->lenBytes; i++) this->data[i] = 0;
}

Key::Key(LengthBits lenbits): lenBits(lenbits), lenBytes(fromLenBitsToLenBytes(lenbits)){
    size_t i;
    union { int integer; char chars[4]; } buff;                                 // -Anonymous union. Casting from 32 bits integer to four chars
    std::random_device dev; std::mt19937 seed(dev());
    std::uniform_int_distribution<std::mt19937::result_type> distribution;      // -Random number with uniform distribution
    this->data = new uint8_t[this->lenBytes];
    for(i = 0; i < this->lenBytes; i += 4) {                                    // -I am supposing everything is fine and lenBytes is a multiple of four
        buff.integer = distribution(seed);                                      // -Taking a random 32 bits integer to divide it into four bytes
        memcpy(reinterpret_cast<char*>(this->data + i), buff.chars, 4);
    }
}

Key::Key(const std::vector<uint8_t>& key_, LengthBits lenbits)
    : lenBits(lenbits), lenBytes(fromLenBitsToLenBytes(lenbits)){
    if(key_.size() < this->lenBytes){
        throw std::invalid_argument(
            "In constructor Key::Key(const std::vector<uint8_t>& key_, LengthBits lenbits): "
            "Insufficient key size: provided " + std::to_string(key_.size()) + " bytes, expected " +
            std::to_string(lenBytes) + " bytes"
        );
    }
    this->data = new uint8_t[this->lenBytes];
    if(!key_.empty()) for(size_t i = 0; i < this->lenBytes; i++) this->data[i] = key_[i];
}

Key::Key(const Key& k): lenBits(k.lenBits), lenBytes(k.lenBytes) {
    size_t i;
    this->data = new uint8_t[k.lenBytes];
    for(i = 0; i < k.lenBytes; i++) this->data[i] = k.data[i];                  // -Supposing Cipher object is well constructed, this is, k.data != nullptr
}

constexpr static const char* keyFileHeaderID = "AESKEY";
constexpr const size_t headerLen = 6;

Key::Key(const char*const fname): lenBits(LengthBits::_128), lenBytes(BLOCK_SIZE) {
    char headerID[headerLen];
    uint16_t keyLen;
    std::ifstream file;
    file.open(fname, std::ios::binary);
    if(file.is_open()) {
        file.read(const_cast<char*>(headerID), static_cast<std::streamsize>(headerLen)); // -Determining if file is a .data file
        if(memcmp(headerID, "AESKEY", headerLen) == 0) {
                file.read(reinterpret_cast<char*>(&keyLen), 2);                                   // -Reading key lenBits
                if(keyLen == uint16_t(LengthBits::_128) || keyLen == uint16_t(LengthBits::_192) || keyLen == uint16_t(LengthBits::_256))
                    this->lenBits = static_cast<LengthBits>(keyLen);
                else {
                    throw std::runtime_error(
                        "In file src/core/key.cpp, function Key::Key(const char*const fname):"
                        + std::to_string(static_cast<int>(keyLen)) + " is not a valid length (in bits) for key.\n"
                    );
                }
                this->lenBytes = fromLenBitsToLenBytes(this->lenBits);          // -lenBytes = lenbits / 8;
                this->data = new uint8_t[this->lenBytes];                       // -Reading key
                file.read(reinterpret_cast<char*>(this->data), static_cast<std::streamsize>(this->lenBytes));
                if (!file || file.gcount() != static_cast<std::streamsize>(this->lenBytes)) {
                    delete[] this->data;
                    this->data = nullptr;
                    throw std::runtime_error(
                        "In file src/core/key.cpp, function Key::Key(const char*const fname): "
                        "File is truncated or corrupted. Expected " + std::to_string(this->lenBytes) +
                        " bytes of key data, but could only read " + std::to_string(file.gcount()) + " bytes.\n"
                    );
                }
           } else {
                throw std::runtime_error(
                    "In file src/core/key.cpp, function Key::Key(const char*const fname): String "
                    + std::string(fname) + " does not represent a valid AES key file.\n"
                );
           }
    } else {
        throw std::runtime_error(
            "In file src/core/key.cpp, function Key::Key(const char*const fname): Failed to open " + std::string(fname)
        );
    }
}

Key::~Key() {
    if(this->data != nullptr) delete[] this->data;
    this->data = nullptr;
}

Key& Key::operator = (const Key& k) {
    if(this != &k) {                                                            // -Guarding against self assignment
        unsigned i;
        if(this->lenBytes != k.lenBytes) {                                // -Modifying length and array containing key only if necessary
            this->lenBits = k.lenBits;
            this->lenBytes = k.lenBytes;
            if(this->data != nullptr) delete[] this->data;
            this->data = new uint8_t[k.lenBytes];
        }
        for(i = 0; i < k.lenBytes; i++) this->data[i] = k.data[i];
    }
    return *this;
}

bool Key::operator == (const Key& k) const{
    unsigned i;
    if(this->lenBytes != k.lenBytes) return false;
    for(i = 0; i < this->lenBytes; i++) if(this->data[i] != k.data[i]) return false;
    return true;
}

bool Key::compareWithRawData(const uint8_t* raw_data, size_t size) const{
    if (size != this->lenBytes) return false;
    return memcmp(this->data, raw_data, size) == 0;
}

Key::LengthBits Key::getLenBits() const{
    return this->lenBits;
}

size_t Key::getLenBytes() const{
    return this->lenBytes;
}

std::ostream& AESencryption::operator<<(std::ostream& ost, const Key& k) {
    ost << "\tKey size: " << static_cast<int>(k.lenBits) << " bits, " << k.lenBytes << " bytes, Nk = " << (k.lenBytes >> 2) << " words\n";
    ost << "\tKey: ";
    print_bytes_as_hex(ost, k.data, k.lenBytes);
    ost << '\n';
    return ost;
}

void Key::save(const char*const fname) const {
    std::ofstream file;
    file.open(fname, std::ios::binary);
    if(file.is_open()) {
        file.write(keyFileHeaderID, headerLen);                                                 // -File type
        file.write(reinterpret_cast<const char*>(&this->lenBits), 2);           // -Key lenBits in bits
        file.write(reinterpret_cast<char*>(this->data), static_cast<std::streamsize>(this->lenBytes));
        if (!file) {
            throw std::runtime_error(
            "In function void Key::save(const char*const fname) const: "
            "Failed to write key data to file: " + std::string(fname)
        );
    }
    } else {
        throw std::runtime_error(
            "In file Source/AES.cpp, function void Key::save(const char* const fname): Failed to write "
            + std::string(fname) + " file.\n"
        );
    }
}

const uint8_t* Key::getDataForTesting() const{
    return this->data;
}

void Key::write_Key(uint8_t*const destination) const {			// -Writes key in destination. Warning: We're supposing we have enough space in
	for(size_t i = 0; i < this->lenBytes; i++) destination[i] = this->data[i]; //  destination array.
}
