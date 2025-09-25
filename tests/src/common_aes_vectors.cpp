/*
 * Common AES Test Vectors and Definitions - Implementation File
 *
 * This file contains the implementations of functions declared in common_aes_vectors.hpp.
 */

#include "../include/common_aes_vectors.hpp"

namespace CommonAESVectors {

// =============================================================================
// Utility Function Implementations
// =============================================================================

size_t getKeyLengthBytes(KeylengthBits klb) {
    switch(klb) {
        case KeylengthBits::keylen128: return 16;
        case KeylengthBits::keylen192: return 24;
        case KeylengthBits::keylen256: return 32;
        default: return 0;
    }
}

const char* getKeylengthString(KeylengthBits keylen) {
    switch(keylen) {
        case KeylengthBits::keylen128: return "128";
        case KeylengthBits::keylen192: return "192";
        case KeylengthBits::keylen256: return "256";
        default: return "Unknown";
    }
}

const char* getOperationString(EncryptionOperationType op) {
    switch(op) {
        case EncryptionOperationType::Encryption: return "Encryption";
        case EncryptionOperationType::Decryption: return "Decryption";
        default: return "Unknown";
    }
}

const unsigned char* retrieveKey(KeylengthBits kl) {
    switch(kl) {
        case KeylengthBits::keylen128: return key128;
        case KeylengthBits::keylen192: return key192;
        case KeylengthBits::keylen256: return key256;
        default: return nullptr;
    }
}

// =============================================================================
// ExampleBase Implementation
// =============================================================================

KeylengthBits ExampleBase::getKeylenBits() const {
    return this->keylenbits;
}

size_t ExampleBase::getKeylenBytes() const {
    switch(this->keylenbits) {
        case KeylengthBits::keylen128: return 16;
        case KeylengthBits::keylen192: return 24;
        case KeylengthBits::keylen256: return 32;
        default: return 0;
    }
}

const unsigned char* ExampleBase::getKey() const {
    return this->key;
}

std::vector<unsigned char> ExampleBase::getKeyAsVector() const {
    return std::vector<unsigned char>(this->key, this->key + this->getKeylenBytes());
}

} // namespace CommonAESVectors
