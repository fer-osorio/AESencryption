/*
 * NIST SP 800-38A Test Vectors - Structured Implementation
 *
 * This file contains test vectors from NIST SP 800-38A Appendix F for:
 * - ECB (Electronic Codebook) mode
 * - CBC (Cipher Block Chaining) mode
 *
 * It relies on "common_aes_vectors.hpp" for base definitions, keys, and
 * common plaintext data.
 */

#ifndef NIST_SP800_38A_EXAMPLES_HPP
#define NIST_SP800_38A_EXAMPLES_HPP

#include "common_aes_vectors.hpp"

// =============================================================================
// Mode-Specific Definitions and Base Classes
// =============================================================================

namespace NISTSP800_38A_Examples {

constexpr size_t TEXT_SIZE = 64;

// Enums specific to modes of operation testing
enum struct OperationMode {
    Unknown,
    ECB,  // Electronic Codebook
    CBC   // Cipher Block Chaining
};

const char* getModeString(OperationMode mode);

// Extends the common base class with members specific to operation modes.
struct ExampleBase : public CommonAESVectors::ExampleBase {
protected:
	CommonAESVectors::EncryptionOperationType operation;
	OperationMode mode;
	const unsigned char* input;
	const unsigned char* expectedOutput;
public:
	CommonAESVectors::EncryptionOperationType getOperationType() const;
	OperationMode getOperationMode() const;
	const unsigned char* getInput() const;
	const unsigned char* getExpectedOutput() const;
	static constexpr size_t getDataSize() { return TEXT_SIZE; }
};

CommonAESVectors::EncryptionOperationType ExampleBase::getOperationType() const {
	return this->operation;
}
OperationMode ExampleBase::getOperationMode() const {
    return this->mode;
}
const unsigned char* ExampleBase::getInput() const {
	return this->input;
}
const unsigned char* ExampleBase::getExpectedOutput() const {
	return this->expectedOutput;
}

// Plaintext used in NIST SP 800-38A mode examples (64 bytes = 4 blocks)
const unsigned char commonPlaintext[TEXT_SIZE] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
};

// Initialization Vector for CBC mode examples
const unsigned char initializationVector[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

// =============================================================================
// ECB Mode Examples (NIST SP 800-38A Appendix F.1)
// =============================================================================

namespace ECB_ns {

// ECB Ciphertexts for each key length using the common plaintext.
const unsigned char ecb_aes128_ciphertext[TEXT_SIZE] = {
    0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97,
    0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d, 0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf,
    0x43, 0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce, 0x23, 0x88, 0x1b, 0x00, 0xe3, 0xed, 0x03, 0x06, 0x88,
    0x7b, 0x0c, 0x78, 0x5e, 0x27, 0xe8, 0xad, 0x3f, 0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5d, 0xd4
};

const unsigned char ecb_aes192_ciphertext[TEXT_SIZE] = {
    0xbd, 0x33, 0x4f, 0x1d, 0x6e, 0x45, 0xf2, 0x5f, 0xf7, 0x12, 0xa2, 0x14, 0x57, 0x1f, 0xa5, 0xcc,
    0x97, 0x41, 0x04, 0x84, 0x6d, 0x0a, 0xd3, 0xad, 0x77, 0x34, 0xec, 0xb3, 0xec, 0xee, 0x4e, 0xef,
    0xef, 0x7a, 0xfd, 0x22, 0x70, 0xe2, 0xe6, 0x0a, 0xdc, 0xe0, 0xba, 0x2f, 0xac, 0xe6, 0x44, 0x4e,
    0x9a, 0x4b, 0x41, 0xba, 0x73, 0x8d, 0x6c, 0x72, 0xfb, 0x16, 0x69, 0x16, 0x03, 0xc1, 0x8e, 0x0e
};

const unsigned char ecb_aes256_ciphertext[TEXT_SIZE] = {
    0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c, 0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8,
    0x59, 0x1c, 0xcb, 0x10, 0xd4, 0x10, 0xed, 0x26, 0xdc, 0x5b, 0xa7, 0x4a, 0x31, 0x36, 0x28, 0x70,
    0xb6, 0xed, 0x21, 0xb9, 0x9c, 0xa6, 0xf4, 0xf9, 0xf1, 0x53, 0xe7, 0xb1, 0xbe, 0xaf, 0xed, 0x1d,
    0x23, 0x30, 0x4b, 0x7a, 0x39, 0xf9, 0xf3, 0xff, 0x06, 0x7d, 0x8d, 0x8f, 0x9e, 0x24, 0xec, 0xc7
};

static const unsigned char* retrieveECBCiphertext(CommonAESVectors::KeylengthBits kl) {
    switch(kl) {
        case CommonAESVectors::KeylengthBits::keylen128: return ecb_aes128_ciphertext;
        case CommonAESVectors::KeylengthBits::keylen192: return ecb_aes192_ciphertext;
        case CommonAESVectors::KeylengthBits::keylen256: return ecb_aes256_ciphertext;
        default: return NULL;
    }
}

struct Example : public ExampleBase {
public:
    Example(CommonAESVectors::KeylengthBits kl, CommonAESVectors::EncryptionOperationType op);
};

Example::Example(CommonAESVectors::KeylengthBits kl, CommonAESVectors::EncryptionOperationType op) {
    this->keylenbits = kl;
    this->mode = OperationMode::ECB;
    this->operation = op;
    this->key = CommonAESVectors::retrieveKey(kl); // Use common function

    switch(op) {
        case CommonAESVectors::EncryptionOperationType::Encryption:
            this->input = commonPlaintext; // Use common plaintext
            this->expectedOutput = retrieveECBCiphertext(kl);
            break;
        case CommonAESVectors::EncryptionOperationType::Decryption:
            this->input = retrieveECBCiphertext(kl);
            this->expectedOutput = commonPlaintext; // Use common plaintext
            break;
        default:
            this->input = NULL;
            this->expectedOutput = NULL;
            break;
    }
}

} // namespace ECB_ns

// =============================================================================
// CBC Mode Examples (NIST SP 800-38A Appendix F.2)
// =============================================================================

namespace CBC_ns {

// CBC Ciphertexts for each key length
const unsigned char cbc_aes128_ciphertext[TEXT_SIZE] = {
    0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
    0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
    0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
    0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7
};

const unsigned char cbc_aes192_ciphertext[TEXT_SIZE] = {
    0x4f, 0x02, 0x1d, 0xb2, 0x43, 0xbc, 0x63, 0x3d, 0x71, 0x78, 0x18, 0x3a, 0x9f, 0xa0, 0x71, 0xe8,
    0xb4, 0xd9, 0xad, 0xa9, 0xad, 0x7d, 0xed, 0xf4, 0xe5, 0xe7, 0x38, 0x76, 0x3f, 0x69, 0x14, 0x5a,
    0x57, 0x1b, 0x24, 0x20, 0x12, 0xfb, 0x7a, 0xe0, 0x7f, 0xa9, 0xba, 0xac, 0x3d, 0xf1, 0x02, 0xe0,
    0x08, 0xb0, 0xe2, 0x79, 0x88, 0x59, 0x88, 0x81, 0xd9, 0x20, 0xa9, 0xe6, 0x4f, 0x56, 0x15, 0xcd
};

const unsigned char cbc_aes256_ciphertext[TEXT_SIZE] = {
    0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6,
    0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d, 0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d,
    0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf, 0xa5, 0x30, 0xe2, 0x63, 0x04, 0x23, 0x14, 0x61,
    0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc, 0xda, 0x6c, 0x19, 0x07, 0x8c, 0x6a, 0x9d, 0x1b
};

static const unsigned char* retrieveCBCCiphertext(CommonAESVectors::KeylengthBits kl) {
    switch(kl) {
        case CommonAESVectors::KeylengthBits::keylen128: return cbc_aes128_ciphertext;
        case CommonAESVectors::KeylengthBits::keylen192: return cbc_aes192_ciphertext;
        case CommonAESVectors::KeylengthBits::keylen256: return cbc_aes256_ciphertext;
        default: return NULL;
    }
}

struct Example : public ExampleBase {
private:
    const unsigned char* iv;

public:
    Example(CommonAESVectors::KeylengthBits kl, CommonAESVectors::EncryptionOperationType op);
    const unsigned char* getIV() const;
    static constexpr size_t getDataSize() { return TEXT_SIZE; }
    static constexpr size_t getIVSize() { return 16; }
};

Example::Example(CommonAESVectors::KeylengthBits kl, CommonAESVectors::EncryptionOperationType op) {
    this->keylenbits = kl;
    this->mode = OperationMode::CBC;
    this->operation = op;
    this->key = CommonAESVectors::retrieveKey(kl); // Use common function
    this->iv = initializationVector; // Use common IV

    switch(op) {
        case CommonAESVectors::EncryptionOperationType::Encryption:
            this->input = commonPlaintext; // Use common plaintext
            this->expectedOutput = retrieveCBCCiphertext(kl);
            break;
        case CommonAESVectors::EncryptionOperationType::Decryption:
            this->input = retrieveCBCCiphertext(kl);
            this->expectedOutput = commonPlaintext; // Use common plaintext
            break;
        default:
            this->input = NULL;
            this->expectedOutput = NULL;
            break;
    }
}

const unsigned char* Example::getIV() const {
	return this->iv;
}

} // namespace CBC_ns

// Helper function to get mode name as string
const char* getModeString(OperationMode mode) {
    switch(mode) {
        case OperationMode::ECB: return "ECB";
        case OperationMode::CBC: return "CBC";
        default: return "Unknown";
    }
}

} // namespace NISTSP800_38A_Examples

/*NISTSP800_38A_Examples::ECB_ns::Example createECBencryptionExample(CommonAESVectors::KeylengthBits klb);
NISTSP800_38A_Examples::CBC_ns::Example createCBCencryptionExample(CommonAESVectors::KeylengthBits klb);*/

NISTSP800_38A_Examples::ECB_ns::Example createECBencryptionExample(CommonAESVectors::KeylengthBits klb){
    return CommonAESVectors::ExampleFactory<NISTSP800_38A_Examples::ECB_ns::Example>::createEncryptionExample(klb);
}

NISTSP800_38A_Examples::CBC_ns::Example createCBCencryptionExample(CommonAESVectors::KeylengthBits klb){
    return CommonAESVectors::ExampleFactory<NISTSP800_38A_Examples::CBC_ns::Example>::createEncryptionExample(klb);
}

#endif // NIST_SP800_38A_EXAMPLES_HPP