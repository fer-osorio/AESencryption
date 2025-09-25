/*
 * AES Key Expansion and Cipher Examples - FIPS 197 Standard Reference - Implementation File
 *
 * This file contains the implementations for the FIPS 197 test vectors
 * for Key Expansion and Cipher examples.
 */

#include "../include/NIST_FIPS197_TestVectors.hpp"

namespace NISTFIPS197_Examples {

// =============================================================================
// Appendix A: Key Expansion Examples Implementation
// =============================================================================

namespace KeyExpansion_ns {

const unsigned char* retrieveKeyExpansion(CommonAESVectors::KeylengthBits kl) {
    switch (kl) {
        case CommonAESVectors::KeylengthBits::keylen128: return key128_expanded;
        case CommonAESVectors::KeylengthBits::keylen192: return key192_expanded;
        case CommonAESVectors::KeylengthBits::keylen256: return key256_expanded;
        default: return nullptr;
    }
}

Example::Example(CommonAESVectors::KeylengthBits kl) {
    this->keylenbits = kl;
    // Uses the key retrieval function from the common header
    this->key = CommonAESVectors::retrieveKey(kl);
    this->expectedKeyExpansion = retrieveKeyExpansion(kl);
}

const unsigned char* Example::getExpectedKeyExpansion() const {
    return this->expectedKeyExpansion;
}

} // namespace KeyExpansion_ns

// =============================================================================
// Appendix B: Cipher Example Implementation
// =============================================================================

namespace Encryption_ns {

// This function is local to this namespace and uses the local keys defined in the header.
const unsigned char* retrieveKey(CommonAESVectors::KeylengthBits kl) {
    switch (kl) {
        case CommonAESVectors::KeylengthBits::keylen128: return key128;
        case CommonAESVectors::KeylengthBits::keylen192: return key192;
        case CommonAESVectors::KeylengthBits::keylen256: return key256;
        default: return nullptr;
    }
}

const unsigned char* retrieveCipherText(CommonAESVectors::KeylengthBits kl) {
    switch (kl) {
        case CommonAESVectors::KeylengthBits::keylen128: return cipherTextKey128;
        case CommonAESVectors::KeylengthBits::keylen192: return cipherTextKey192;
        case CommonAESVectors::KeylengthBits::keylen256: return cipherTextKey256;
        default: return nullptr;
    }
}

Example::Example(CommonAESVectors::KeylengthBits kl, CommonAESVectors::EncryptionOperationType encOpType) {
    this->encOpType_ = encOpType;
    this->keylenbits = kl;
    this->key = Encryption_ns::retrieveKey(kl); // Uses the local retrieveKey function

    switch (encOpType) {
        case CommonAESVectors::EncryptionOperationType::Encryption:
            this->input = plainText;
            this->expectedOutput = retrieveCipherText(kl);
            break;
        case CommonAESVectors::EncryptionOperationType::Decryption:
            this->input = retrieveCipherText(kl);
            this->expectedOutput = plainText;
            break;
        case CommonAESVectors::EncryptionOperationType::Unknown:
            this->input = nullptr;
            this->expectedOutput = nullptr;
            break;
    }
}

const unsigned char* Example::getInput() const {
    return this->input;
}

const unsigned char* Example::getExpectedOutput() const {
    return this->expectedOutput;
}

} // namespace Encryption_ns

} // namespace NISTFIPS197_Examples
