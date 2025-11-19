/*
 * Common AES Test Vectors and Definitions - Header File
 *
 * This file extracts common components from FIPS 197 and NIST SP 800-38A
 * example files to provide a single, reusable header for AES implementations.
 *
 * It includes:
 * - Enumeration for standard AES key sizes.
 * - Common keys used in FIPS 197 and NIST SP 800-38A examples.
 * - Stub/mock test data for independent component testing.
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

namespace Common {

    // =============================================================================
    // Common Enumerations
    // =============================================================================

    /**
     * @brief Defines the standard AES key sizes in bits.
     */
    enum struct KeySize {
        UnknownKeySize,
        AES128 = 128,
        AES192 = 192,
        AES256 = 256
    };

    /**
     * @brief Defines the type of cryptographic operation.
     */
    enum struct Direction {
        Encryption,
        Decryption
    };

    /**
     * @brief Defines the type of test vector source.
     */
    enum struct VectorSource {
        NIST_Official,    // Official NIST test vectors
        Stub_Sequential,  // Simple sequential bytes (0x00, 0x01, 0x02, ...)
        Stub_Zeros,       // All zeros
        Stub_Ones,        // All ones (0xFF)
        Stub_Alternating  // Alternating pattern (0xAA, 0x55, ...)
    };

    // =============================================================================
    // Function Declarations
    // =============================================================================

    size_t getKeySizeBytes(KeySize ks);
    const char* getKeySizeString(KeySize ks);
    const char* getDirectionString(Direction dir);
    const char* getVectorSourceString(VectorSource vs);
    const unsigned char* getKey(KeySize ks);
    const unsigned char* getStubKey(KeySize ks, VectorSource vs);

    // =============================================================================
    // Common Base Classes
    // =============================================================================

    /**
     * @brief A base class for test examples, providing common key information.
     */
    struct TestVectorBase {
    protected:
        KeySize keySize;
        const unsigned char* key;

    public:
        virtual ~TestVectorBase() = default;

        /**
         * @brief Gets the key size enumeration.
         * @return The key size as a KeySize enum value.
         */
        KeySize getKeySize() const;

        /**
         * @brief Gets the size of the key in bytes.
         * @return The key size (16, 24, or 32) or 0 for unknown.
         */
        size_t getKeySizeBytes() const;

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
    // Common Test Data (Keys, Plaintext, IV) - NIST Official
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
    // Stub/Mock Test Data for Independent Component Testing
    // =============================================================================

    // Sequential stub keys - useful for debugging and visual inspection
    constexpr unsigned char stub_key128_sequential[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    constexpr unsigned char stub_key192_sequential[24] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
    };

    constexpr unsigned char stub_key256_sequential[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };

    // Zero stub keys - useful for testing edge cases
    constexpr unsigned char stub_key128_zeros[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    constexpr unsigned char stub_key192_zeros[24] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    constexpr unsigned char stub_key256_zeros[32] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    // Ones stub keys - useful for testing bit manipulation
    constexpr unsigned char stub_key128_ones[16] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };

    constexpr unsigned char stub_key192_ones[24] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };

    constexpr unsigned char stub_key256_ones[32] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };

    // Alternating pattern stub keys - useful for detecting bit flipping
    constexpr unsigned char stub_key128_alternating[16] = {
        0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55,
        0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55
    };

    constexpr unsigned char stub_key192_alternating[24] = {
        0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55,
        0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55,
        0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55
    };

    constexpr unsigned char stub_key256_alternating[32] = {
        0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55,
        0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55,
        0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55,
        0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55
    };

    // Stub plaintext blocks
    constexpr unsigned char stub_plaintext_zeros[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    constexpr unsigned char stub_plaintext_sequential[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    constexpr unsigned char stub_plaintext_ones[16] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };

    // Stub initialization vectors
    constexpr unsigned char stub_iv_zeros[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    constexpr unsigned char stub_iv_sequential[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    constexpr unsigned char stub_iv_ones[16] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };

    // Stub counters
    constexpr unsigned char stub_counter_zeros[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    constexpr unsigned char stub_counter_sequential[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    constexpr unsigned char stub_counter_ones[16] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };

    // =============================================================================
    // Template Definitions
    // =============================================================================

    /**
     * @brief Template factory class for creating test vectors of different operation types.
     */
    template<typename TestVectorClass>
    struct TestVectorFactory {
        static TestVectorClass createEncryptionTestVector(KeySize ks) {
            return TestVectorClass(ks, Direction::Encryption);
        }

        static TestVectorClass createDecryptionTestVector(KeySize ks) {
            return TestVectorClass(ks, Direction::Decryption);
        }
    };

} // namespace Common

// =============================================================================
// Utility Macros
// =============================================================================

#define COMMON_KEYSZ Common::KeySize
#define COMMON_DIR_ENC Common::Direction::Encryption
#define COMMON_DIR_DEC Common::Direction::Decryption
#define COMMON_VECTSRC Common::VectorSource
#define COMMON_GETKEYSZSTR(ks) Common::getKeySizeString(static_cast<COMMON_KEYSZ>(ks))
#define COMMON_GETSTUBKEY(ks, vs) Common::getStubKey(static_cast<COMMON_KEYSZ>(ks), static_cast<COMMON_VECTSRC>(vs))

#endif // COMMON_AES_VECTORS_HPP
