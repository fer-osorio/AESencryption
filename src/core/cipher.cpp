#include"../../data-encryption/include/constants.h"
#include"../../data-encryption/include/AES.h"
#include"../../data-encryption/include/operation_modes.h"
#include"../../include/cipher.hpp"
#include"../utils/include/print_bytes.hpp"
#include<cstring>
#include<chrono>

struct AESencryption::InitVector{
    uint8_t data[BLOCK_SIZE];
};

// Custom exception classes for better error categorization
class AESencryption::AESException : public std::runtime_error {
public:
    explicit AESException(const std::string& message) : std::runtime_error(message) {}
};

class AESencryption::KeyExpansionException : public AESException {
public:
    explicit KeyExpansionException(const std::string& message)
        : AESException("Key expansion error: " + message) {}
};

class AESencryption::EncryptionException : public AESException {
public:
    explicit EncryptionException(const std::string& message)
        : AESException("Encryption error: " + message) {}
};

class AESencryption::DecryptionException : public AESException {
public:
    explicit DecryptionException(const std::string& message)
        : AESException("Decryption error: " + message) {}
};

using namespace AESencryption;

static size_t getNkfromLenbit(Key::LengthBits lb){
    return size_t(lb)/32;
}
static size_t getNrFromNk(size_t Nk){
    return Nk+6;
}
static size_t getKeyExpansionByteLenFromNr(size_t Nr){
    return (Nr+1)*NB*4;
}

Cipher::OperationMode::OperationMode(){}

Cipher::OperationMode::OperationMode(Identifier ID) : ID_(ID){
    switch(ID){
        case Identifier::ECB:
            break;
        case Identifier::CBC:
            this->IV_ = new InitVector;
            break;
    }
}

Cipher::OperationMode::OperationMode(const OperationMode& optMode): ID_(optMode.ID_){
    if(optMode.IV_ != NULL){
        this->IV_ = new InitVector;
        std::memcpy(this->IV_->data, optMode.IV_, BLOCK_SIZE);
    }
}

Cipher::OperationMode& Cipher::OperationMode::operator=(const OperationMode& optMode){
    if(this != &optMode){
        this->ID_ = optMode.ID_;
        if(optMode.IV_!=NULL){
            if(this->IV_ == NULL) this->IV_ = new InitVector;
            std::memcpy(this->IV_->data, optMode.IV_, BLOCK_SIZE);
        } else {
            delete this->IV_; this->IV_ = NULL;
        }
    }
    return *this;
}

Cipher::OperationMode::Identifier Cipher::OperationMode::getOperationModeID() const{
    return this->ID_;
}

const uint8_t* Cipher::OperationMode::getIVpointerData() const{
    return this->IV_->data;
}

Cipher::OperationMode::~OperationMode(){
    if(this->IV_ != NULL) delete this->IV_;
}

Cipher::OperationMode Cipher::OperationMode::buildInCBCmode(const InitVector& IVsource){
    OperationMode optMode(OperationMode::Identifier::CBC);
    std::memcpy(optMode.IV_->data, IVsource.data, BLOCK_SIZE);
    return optMode;
}

Cipher::Config::Config(): Nk_(NK128), Nr(NR128), keyExpansionLengthBytes(KEY_EXPANSION_LENGTH_128_BYTES) {}

Cipher::Config::Config(OperationMode optMode, size_t Nk)
    :operationMode(optMode), Nk_(Nk), Nr(getNrFromNk(Nk)), keyExpansionLengthBytes(getKeyExpansionByteLenFromNr(this->Nr)){
}

Cipher::OperationMode::Identifier Cipher::Config::getOperationModeID() const{
    return this->operationMode.getOperationModeID();
}

size_t Cipher::Config::getNk() const{
    return this->Nk_;
}

size_t Cipher::Config::getNr() const{
    return this->Nr;
}

size_t Cipher::Config::getKeyExpansionLengthBytes() const{
    return this->keyExpansionLengthBytes;
}

const uint8_t* Cipher::Config::getIVpointerData() const{
    return this->operationMode.getIVpointerData();
}

Cipher::Cipher(): config(OperationMode::Identifier::ECB, Nk128) {
    size_t keyExpLen = this->config.getKeyExpansionLengthBytes();
    this->keyExpansion = new uint8_t[keyExpLen];
    for(size_t i = 0; i < keyExpLen; i++) this->keyExpansion[i] = 0;            // -Since the key constitutes of just zeros, key expansion is also just zeros
}

Cipher::Cipher(const Key& k, const OperationMode::Identifier optModeID): key(k) {
    this->buildKeyExpansion();
    this->config = Config(this->buildOperationMode(optModeID), getNkfromLenbit(k.lenBits));
}

Cipher::Cipher(const Cipher& c): key(c.key), config(c.config) {
    size_t keyExpLen = c.config.getKeyExpansionLengthBytes();
    this->keyExpansion = new uint8_t[keyExpLen];
    for(size_t i = 0; i < keyExpLen; i++) this->keyExpansion[i] = c.keyExpansion[i];
}

Cipher::~Cipher() {
    if(keyExpansion != NULL) delete[] keyExpansion;
    keyExpansion = NULL;
}

Cipher& Cipher::operator = (const Cipher& c) {
    if(this != &c) {
        size_t ckeyExpLen = config.getKeyExpansionLengthBytes();
        this->key = c.key;
        if(this->config.getKeyExpansionLengthBytes() != ckeyExpLen) {
            if(this->keyExpansion != NULL) delete[] keyExpansion;
            this->keyExpansion = new uint8_t[ckeyExpLen];
        }
        std::memcpy(this->keyExpansion, c.keyExpansion, ckeyExpLen);
        this->config = c.config;
    }
    return *this;
}

std::ostream& AESencryption::operator<<(std::ostream& ost, const Cipher& c) {
    ost << "AES::Cipher object information:\n";
    ost << c.key;
    ost << "\tNr: " << c.config.getNr() << " rounds\n";
    ost << "\tKey Expansion size: " << c.config.getKeyExpansionLengthBytes() << " bytes\n";
    ost << "\tKey Expansion:";

    const size_t bytes_per_row = 32;
    size_t bytes_to_print;
    size_t cKeyExpLen = c.config.getKeyExpansionLengthBytes();
    if (c.keyExpansion) {
        for(size_t i = 0; i < cKeyExpLen; i += bytes_per_row) {
            ost << "\n\t\t"; // Start each new line of the expansion
            // Determine how many bytes to print in this row (handles the last partial row). Here, we are supposing KeyLenExp is a multiple of 32,
            // which is true for AES standard.
            bytes_to_print = (i + bytes_per_row > cKeyExpLen) ? (cKeyExpLen - i) : bytes_per_row;
            print_bytes_as_hex(ost, &c.keyExpansion[i], bytes_to_print);
        }
    } else {
        ost << " (null)";
    }
    ost << '\n';
    return ost;
}

Cipher::OperationMode Cipher::buildOperationMode(const OperationMode::Identifier optModeID){
    switch(optModeID){
        case OperationMode::Identifier::ECB:
            return OperationMode(optModeID);
            break;
        case OperationMode::Identifier::CBC:
            InitVector IVbuff;
            union {
                uint8_t  data08[BLOCK_SIZE];
                uint64_t data64[2];
            } tt;
            tt.data64[0] = std::chrono::high_resolution_clock::now().time_since_epoch().count();
            tt.data64[1] = tt.data64[0]++;
            if(this->keyExpansion != NULL)
                encryptECB(tt.data08, BLOCK_SIZE, this->keyExpansion, static_cast<size_t>(this->key.getLenBits()), IVbuff.data);
            return OperationMode::buildInCBCmode(IVbuff);
            break;
    }
    return OperationMode(optModeID);
}

void Cipher::buildKeyExpansion() {
    KeyExpansion_t* ke_p = KeyExpansionMemoryAllocationBuild(this->key.data, static_cast<size_t>(this->key.getLenBits()), false);
    if(this->keyExpansion == NULL) this->keyExpansion = new uint8_t[this->config.getKeyExpansionLengthBytes()];
    KeyExpansionWriteBytes(ke_p, this->keyExpansion);
    KeyExpansionDelete(&ke_p);
}

void Cipher::encrypt(const uint8_t*const data, size_t size, uint8_t*const output) const{
    if(size == 0 || data == NULL) return;
    size_t thisKeylenbits = static_cast<size_t>(this->key.getLenBits());
    OperationMode::Identifier optMode = this->config.getOperationModeID();
    switch(optMode) {
        case OperationMode::Identifier::ECB:
            encryptECB(data, size, this->keyExpansion, thisKeylenbits, output);
            break;
        case OperationMode::Identifier::CBC:
            encryptCBC(data, size, this->keyExpansion, thisKeylenbits, this->config.getIVpointerData(), output);
            break;
    }
}

void Cipher::decrypt(const uint8_t*const data, size_t size, uint8_t*const output) const{
    if(size == 0 || data == NULL) return;
    size_t thisKeylenbits = static_cast<size_t>(this->key.getLenBits());
    OperationMode::Identifier optMode = this->config.getOperationModeID();
    switch(optMode) {
        case OperationMode::Identifier::ECB:
            decryptECB(data, size, this->keyExpansion, thisKeylenbits, output);
            break;
        case OperationMode::Identifier::CBC:
            decryptCBC(data, size, this->keyExpansion, thisKeylenbits, this->config.getIVpointerData(), output);
            break;
    }
}

void Cipher::encryption(std::vector<uint8_t>& data) const{
    encrypt(data.data(), data.size(), data.data());
}

void Cipher::decryption(std::vector<uint8_t>& data) const{
    decrypt(data.data(), data.size(), data.data());
}

void Cipher::saveKey(const char*const fname) const{ this->key.save(fname); }
Cipher::OperationMode Cipher::getOptModeID() const{ return this->config.getOperationModeID(); }
