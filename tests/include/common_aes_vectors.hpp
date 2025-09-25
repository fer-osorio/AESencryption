/*
 * Common AES Test Vectors and Definitions - Header File
 *
 * This file extracts common components from FIPS 197 and NIST SP 800-38A
 * example files to provide a single, reusable header for AES implementations.
 *
 * It includes:
 * - Enumeration for standard AES key lengths.
 * - Common keys used in FIPS 197 and NIST SP 800-38A examples.
 * - A common plaintext block and initialization vector.
 * - A base class for structuring test examples.
 * - Helper functions for retrieving keys and converting enums to strings.
 *
 * All arrays use byte representation in big-endian format.
 */

#ifndef COMMON_AES_VECTORS_HPP
#define COMMON_AES_VECTORS_HPP

#include <stddef.h>
#include <vector>

namespace CommonAESVectors {

// =============================================================================
// Common Enumerations
// =============================================================================

/**
 * @brief Defines the standard AES key lengths in bits.
 */
enum struct KeylengthBits {
    UnknownKeylen,
    keylen128 = 128,
    keylen192 = 192,
    keylen256 = 256
};

/**
 * @brief Defines the type of cryptographic operation.
 */
enum struct EncryptionOperationType {
    Unknown,
    Encryption,
    Decryption
};

// =============================================================================
// Function Declarations
// =============================================================================

size_t getKeyLengthBytes(KeylengthBits klb);
const char* getKeylengthString(KeylengthBits keylen);
const char* getOperationString(EncryptionOperationType op);
const unsigned char* retrieveKey(KeylengthBits kl);

// =============================================================================
// Common Base Classes
// =============================================================================

/**
 * @brief A base class for test examples, providing common key information.
 */
struct ExampleBase {
protected:
    KeylengthBits keylenbits;
    const unsigned char* key;

public:
    virtual ~ExampleBase() = default;

    /**
     * @brief Gets the key length enumeration.
     * @return The key length as a KeylengthBits enum value.
     */
    KeylengthBits getKeylenBits() const;

    /**
     * @brief Gets the size of the key in bytes.
     * @return The key size (16, 24, or 32) or 0 for unknown.
     */
    size_t getKeylenBytes() const;

    /**
     * @brief Gets a pointer to the raw key data.
     * @return A const pointer to the key array.
     */
    const unsigned char* getKey() const;

    /**
     * @brief Gets the key as a std::vector.
     * @return A vector containing the key bytes.
     */
    std::vector<unsigned char> getKeyAsVector() const;
};

// =============================================================================
// Common Test Data (Keys, Plaintext, IV)
// =============================================================================

// These keys are specified in FIPS 197 Appendix C and used across
// NIST SP 800-38A examples for AES-128, AES-192, and AES-256.

constexpr unsigned char key128[16] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

constexpr unsigned char key192[24] = {
    0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
    0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
    0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
};

constexpr unsigned char key256[32] = {
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
    0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
    0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
};

// =============================================================================
// Template Definitions
// =============================================================================

/**
 * @brief Template factory class for creating examples of different operation types.
 */
template<typename ExampleType>
struct ExampleFactory {
    static ExampleType createEncryptionExample(KeylengthBits keylen) {
        return ExampleType(keylen, EncryptionOperationType::Encryption);
    }

    static ExampleType createDecryptionExample(KeylengthBits keylen) {
        return ExampleType(keylen, EncryptionOperationType::Decryption);
    }
};

} // namespace CommonAESVectors

// =============================================================================
// Utility Macros
// =============================================================================

#define COMAESVEC_KEYLEN CommonAESVectors::KeylengthBits
#define COMAESVEC_OPERTENCRYPT CommonAESVectors::EncryptionOperationType::Encryption
#define COMAESVEC_OPERTDECRYPT CommonAESVectors::EncryptionOperationType::Decryption
#define COMAESVEC_GETKEYLENSTR(klb) CommonAESVectors::getKeylengthString(static_cast<COMAESVEC_KEYLEN>(klb))

#endif // COMMON_AES_VECTORS_HPP