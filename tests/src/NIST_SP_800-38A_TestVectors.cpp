/*
 * NIST SP 800-38A Test Vectors - Implementation File
 *
 * This file contains the implementations for the NIST SP 800-38A test vectors
 * for ECB and CBC modes.
 */

#include "../include/NIST_SP_800-38A_TestVectors.hpp"
#include <map>

namespace NISTSP800_38A_Examples {

// =============================================================================
// Utility Functions Implementation
// =============================================================================

const char* getModeString(OperationMode mode) {
    switch(mode) {
        case OperationMode::ECB: return "ECB";
        case OperationMode::CBC: return "CBC";
        default: return "Unknown";
    }
}

const unsigned char* getInitializationVector() {
    return initializationVector;
}

std::vector<unsigned char> getInitializationVectorAsStdVector() {
    return std::vector<unsigned char>(initializationVector, initializationVector + INITIALIZATION_VECTOR_SIZE);
}

// =============================================================================
// ExampleBase Implementation
// =============================================================================

CommonAESVectors::EncryptionOperationType ExampleBase::getOperationType() const {
    return this->operation;
}

OperationMode ExampleBase::getOperationMode() const {
    return this->mode;
}

const unsigned char* ExampleBase::getInput() const {
    return this->input;
}

std::vector<unsigned char> ExampleBase::getInputAsVector() const {
    return std::vector<unsigned char>(this->input, this->input + TEXT_SIZE);
}

const unsigned char* ExampleBase::getExpectedOutput() const {
    return this->expectedOutput;
}

std::vector<unsigned char> ExampleBase::getExpectedOutputAsVector() const {
    return std::vector<unsigned char>(this->expectedOutput, this->expectedOutput + TEXT_SIZE);
}

// =============================================================================
// ECB Mode Implementation
// =============================================================================

namespace ECB_ns {

const unsigned char* retrieveECBCiphertext(CommonAESVectors::KeylengthBits klb) {
    switch(klb) {
        case CommonAESVectors::KeylengthBits::keylen128: return ecb_aes128_ciphertext;
        case CommonAESVectors::KeylengthBits::keylen192: return ecb_aes192_ciphertext;
        case CommonAESVectors::KeylengthBits::keylen256: return ecb_aes256_ciphertext;
        default: return nullptr;
    }
}

Example::Example(CommonAESVectors::KeylengthBits klb, CommonAESVectors::EncryptionOperationType op) {
    this->keylenbits = klb;
    this->mode = OperationMode::ECB;
    this->operation = op;
    this->key = CommonAESVectors::retrieveKey(klb); // Use common function

    switch(op) {
        case CommonAESVectors::EncryptionOperationType::Encryption:
            this->input = commonPlaintext; // Use common plaintext
            this->expectedOutput = retrieveECBCiphertext(klb);
            break;
        case CommonAESVectors::EncryptionOperationType::Decryption:
            this->input = retrieveECBCiphertext(klb);
            this->expectedOutput = commonPlaintext; // Use common plaintext
            break;
        default:
            this->input = nullptr;
            this->expectedOutput = nullptr;
            break;
    }
}

} // namespace ECB_ns

// =============================================================================
// CBC Mode Implementation
// =============================================================================

namespace CBC_ns {

const unsigned char* retrieveCBCCiphertext(CommonAESVectors::KeylengthBits klb) {
    switch(klb) {
        case CommonAESVectors::KeylengthBits::keylen128: return cbc_aes128_ciphertext;
        case CommonAESVectors::KeylengthBits::keylen192: return cbc_aes192_ciphertext;
        case CommonAESVectors::KeylengthBits::keylen256: return cbc_aes256_ciphertext;
        default: return nullptr;
    }
}

Example::Example(CommonAESVectors::KeylengthBits klb, CommonAESVectors::EncryptionOperationType op) {
    this->keylenbits = klb;
    this->mode = OperationMode::CBC;
    this->operation = op;
    this->key = CommonAESVectors::retrieveKey(klb); // Use common function
    this->iv = initializationVector; // Use common IV

    switch(op) {
        case CommonAESVectors::EncryptionOperationType::Encryption:
            this->input = commonPlaintext; // Use common plaintext
            this->expectedOutput = retrieveCBCCiphertext(klb);
            break;
        case CommonAESVectors::EncryptionOperationType::Decryption:
            this->input = retrieveCBCCiphertext(klb);
            this->expectedOutput = commonPlaintext; // Use common plaintext
            break;
        default:
            this->input = nullptr;
            this->expectedOutput = nullptr;
            break;
    }
}

const unsigned char* Example::getIV() const {
    return this->iv;
}

} // namespace CBC_ns

// =============================================================================
// Factory Functions Implementation
// =============================================================================

std::unique_ptr<ExampleBase> makeExampleECB(CommonAESVectors::KeylengthBits klb) {
    return std::make_unique<ECB_ns::Example>(klb, CommonAESVectors::EncryptionOperationType::Encryption);
}

std::unique_ptr<ExampleBase> makeExampleCBC(CommonAESVectors::KeylengthBits klb) {
    return std::make_unique<CBC_ns::Example>(klb, CommonAESVectors::EncryptionOperationType::Encryption);
}

// The map that connects the enum to the factory function
static const std::map<OperationMode, ExampleFactory> factoryMap = {
    { OperationMode::ECB, &makeExampleECB },
    { OperationMode::CBC, &makeExampleCBC }
    // To add a new mode, you just add a new line here
};

/**
 * @brief Factory dispatcher using a map lookup.
 */
std::unique_ptr<ExampleBase> createExample(CommonAESVectors::KeylengthBits klb, OperationMode mode) {
    auto it = factoryMap.find(mode);
    if (it != factoryMap.end()) {
        // 'it->second' holds the function (e.g., &makeExampleCBC),
        // so we call it with the key length.
        return it->second(klb);
    }
    return nullptr; // Mode not found in map
}

} // namespace NISTSP800_38A_Examples
