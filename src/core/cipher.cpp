#include"../../data-encryption/include/constants.h"
#include"../../data-encryption/include/AES.h"
#include"../../data-encryption/include/operation_modes.h"
#include"../../include/cipher.hpp"
#include"../utils/print_bytes.hpp"
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

// Error code to exception mapping
static void handleExceptionCode(enum ExceptionCode code, const std::string& operation) {
    if(code == NoException) return;                                             // Success

    std::string base_msg = operation + " failed: ";
    switch (code) {
        case NullKey:
            throw std::invalid_argument(base_msg + "Key is null");
        case NullKeyExpansion:
            throw KeyExpansionException("Key expansion is null");
        case NullSource:
            throw std::invalid_argument(base_msg + "Source is null");
        case NullDestination:
            throw std::invalid_argument(base_msg + "Destination is null");
        case NullInput:
            throw std::invalid_argument(base_msg + "Input is null");
        case NullOutput:
            throw std::invalid_argument(base_msg + "Output is null");
        case NullInitialVector:
            throw std::invalid_argument(base_msg + "Initial vector is null");
        case ZeroLength:
            throw std::invalid_argument(base_msg + "Length is zero");
        case InvalidKeyLength:
            throw KeyExpansionException("Invalid key length");
        case InvalidInputSize:
            throw std::invalid_argument(base_msg + "Input size is invalid (must be al least 16 bytes)");
        case UnknownOperation:
            throw std::invalid_argument(base_msg + "Unknown operation");
        default:
            throw AESException(base_msg + "Unknown error code: " + std::to_string(static_cast<int>(code)));
    }
}

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
        case Identifier::Unknown:
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

Cipher::Config::Config(OperationMode optMode, Key::LengthBits klb):
    operationMode(optMode),
    Nk_(getNkfromLenbit(klb)),
    Nr(getNrFromNk(this->Nk_)),
    keyExpansionLengthBytes(getKeyExpansionByteLenFromNr(this->Nr)){
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

Cipher::Cipher(): config(OperationMode::Identifier::ECB, Key::LengthBits::_128) {
    size_t keyExpLen = this->config.getKeyExpansionLengthBytes();
    this->keyExpansion = new uint8_t[keyExpLen];
    for(size_t i = 0; i < keyExpLen; i++) this->keyExpansion[i] = 0;            // -Since the default key constitutes of just zeros, key expansion is also just zeros
}

Cipher::Cipher(const Key& k, const OperationMode::Identifier optModeID): key(k), config(optModeID, k.getLenBits()) {
    this->buildKeyExpansion();
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
        case OperationMode::Identifier::Unknown:
            return OperationMode(optModeID);
    }
    return OperationMode(optModeID);
}

void Cipher::buildKeyExpansion() {
    // Validate input first at C++ level for better error messages
    if (this->key.data == nullptr) {
        throw KeyExpansionException("Key data is null");
    }
    size_t keylenBits = static_cast<size_t>(this->key.getLenBits());
    if (keylenBits != 128 && keylenBits != 192 && keylenBits != 256) {
        throw KeyExpansionException("Invalid key length: " + std::to_string(keylenBits) + " bits (must be 128, 192, or 256)");
    }

    // Build key expansion using C function
    KeyExpansion_t* ke_p = KeyExpansionMemoryAllocationBuild(this->key.data, keylenBits, false);
    if (ke_p == NULL) {
        throw KeyExpansionException("Failed to allocate key expansion object");
    }

    try {
        // Allocate memory for key expansion bytes if not already allocated
        if (this->keyExpansion == nullptr) {
            size_t expansion_size = this->config.getKeyExpansionLengthBytes();
            if(expansion_size == 0) {
                throw KeyExpansionException("Invalid key expansion size");
            }
            this->keyExpansion = new uint8_t[expansion_size];
        }
        // Write key expansion bytes
        KeyExpansionWriteBytes(ke_p, this->keyExpansion);
        // Clean up C object
        KeyExpansionDelete(&ke_p);
    } catch (...) {
        // Ensure C resources are cleaned up even if exception occurs
        if (ke_p != NULL) {
            KeyExpansionDelete(&ke_p);
        }
        throw; // Re-throw the exception
    }
}

void Cipher::encrypt(const uint8_t*const data, size_t size, uint8_t*const output) const{
    // Validate inputs at C++ level for immediate feedback
    if (data == nullptr) {
        throw std::invalid_argument("Encryption failed: Input data cannot be null");
    }

    if (output == nullptr) {
        throw std::invalid_argument("Encryption failed: Output buffer cannot be null");
    }

    if (size == 0) {
        throw std::invalid_argument("Encryption failed: Data size cannot be zero");
    }

    // Check block alignment for block cipher modes
    if (size < BLOCK_SIZE) {
        throw std::invalid_argument("Encryption failed: Data size (" + std::to_string(size) +
                                   ") must be at least (" + std::to_string(BLOCK_SIZE) + " bytes)");
    }

    if (this->keyExpansion == nullptr) {
        throw EncryptionException("Key expansion not initialized - call buildKeyExpansion() first");
    }

    // Perform encryption
    size_t keylenBits = static_cast<size_t>(this->key.getLenBits());
    OperationMode::Identifier opt_mode = this->config.getOperationModeID();
    enum ExceptionCode result;

    switch (opt_mode) {
        case OperationMode::Identifier::ECB:
            result = encryptECB(data, size, this->keyExpansion, keylenBits, output);
            handleExceptionCode(result, "ECB encryption");
            break;
        case OperationMode::Identifier::CBC:
            {   // New scope, avoiding "cannot jump" error
                const uint8_t* iv = this->config.getIVpointerData();
                if (iv == nullptr) {
                    throw EncryptionException("IV is required for CBC mode but not set");
                }
                result = encryptCBC(data, size, this->keyExpansion, keylenBits, iv, output);
                handleExceptionCode(result, "CBC encryption");
            }
            break;
        default:
            throw EncryptionException("Unsupported operation mode: " + std::to_string(static_cast<int>(opt_mode)));
    }
}

void Cipher::decrypt(const uint8_t*const data, size_t size, uint8_t*const output) const{
    // Validate inputs (same validation as encrypt)
    if (data == nullptr) {
        throw std::invalid_argument("Decryption failed: Input data cannot be null");
    }

    if (output == nullptr) {
        throw std::invalid_argument("Decryption failed: Output buffer cannot be null");
    }

    if (size == 0) {
        throw std::invalid_argument("Decryption failed: Data size cannot be zero");
    }

    if (size < BLOCK_SIZE) {
        throw std::invalid_argument("Decryption failed: Data size (" + std::to_string(size) +
                                   ") must be at least (" + std::to_string(BLOCK_SIZE) + " bytes)");
    }

    if (this->keyExpansion == nullptr) {
        throw DecryptionException("Key expansion not initialized - call buildKeyExpansion() first");
    }

    // Perform decryption
    size_t key_len_bits = static_cast<size_t>(this->key.getLenBits());
    OperationMode::Identifier opt_mode = this->config.getOperationModeID();
    enum ExceptionCode result;

    switch (opt_mode) {
        case OperationMode::Identifier::ECB:
            result = decryptECB(data, size, this->keyExpansion, key_len_bits, output);
            handleExceptionCode(result, "ECB decryption");
            break;
        case OperationMode::Identifier::CBC:
            {   // New scope, avoiding "cannot jump" error
                const uint8_t* iv = this->config.getIVpointerData();
                if (iv == nullptr) {
                    throw DecryptionException("IV is required for CBC mode but not set");
                }
                result = decryptCBC(data, size, this->keyExpansion, key_len_bits, iv, output);
                handleExceptionCode(result, "CBC decryption");
            }
            break;
        default:
            throw DecryptionException("Unsupported operation mode: " + std::to_string(static_cast<int>(opt_mode)));
    }
}

void Cipher::encryption(const std::vector<uint8_t>& input, std::vector<uint8_t>& output) const{
    if (input.empty()) {
        throw std::invalid_argument("Input data vector cannot be empty");
    }

    if (output.empty()) {
        throw std::invalid_argument("Output data vector cannot be empty");
    }
    if(output.size() < input.size()){
        throw std::invalid_argument(
            "In member function Cipher::encryption(const std::vector<uint8_t>& input, std::vector<uint8_t>& output): "
            "output vector size most be bigger or equal than input vector size"
        );
    }
    if(input.size() < BLOCK_SIZE){
        throw std::invalid_argument("Input size must be at least one block size");
    }
    try{
        this->encrypt(input.data(), input.size(), output.data());
    } catch(...){
        throw;
    }
}

void Cipher::decryption(const std::vector<uint8_t>& input, std::vector<uint8_t>& output) const{
    // Validate inputs (same validation as encryption)
    if (input.empty()) {
        throw std::invalid_argument("Input data vector cannot be empty");
    }

    if (output.empty()) {
        throw std::invalid_argument("Output data vector cannot be empty");
    }
    if(output.size() < input.size()){
        throw std::invalid_argument(
            "In member function Cipher::decryption(const std::vector<uint8_t>& input, std::vector<uint8_t>& output):"
            "output vector size most be bigger or equal than input vector size"
        );
    }
    if(input.size() < BLOCK_SIZE){
        throw std::invalid_argument("Input size must be at least one block size");
    }
    try{
        this->decrypt(input.data(), input.size(), output.data());
    } catch(...){
        throw;
    }
}

void Cipher::saveKey(const char*const fname) const{
    this->key.save(fname);
}
Cipher::OperationMode Cipher::getOptModeID() const{
    return this->config.getOperationModeID();
}

// Testing helper methods
const uint8_t* Cipher::getKeyExpansionForTesting() const {
    return this->keyExpansion;
}
bool Cipher::isKeyExpansionInitialized() const {
    return this->keyExpansion != nullptr;
}

const uint8_t* Cipher::getInitialVectorForTesting() const{
    return this->config.getIVpointerData();
}
