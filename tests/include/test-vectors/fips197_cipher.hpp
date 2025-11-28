/**
 * @file fips197_cipher.hpp
 * @brief FIPS 197 Appendix B & C - Cipher Test Vectors
 *
 * Contains official NIST test vectors for validating complete AES
 * encryption and decryption operations.
 *
 * @note These use different keys than the Key Expansion examples!
 */

#ifndef TEST_VECTORS_FIPS197_CIPHER_HPP
#define TEST_VECTORS_FIPS197_CIPHER_HPP

#include "common.hpp"
#include <memory>

namespace TestVectors {
    namespace AES {
        namespace FIPS197 {
            namespace Cipher {

                // =========================================================================
                // Plaintext Data
                // =========================================================================

                /// Common plaintext used across all key sizes: 00112233445566778899aabbccddeeff
                extern const unsigned char kPlainText[16];

                // =========================================================================
                // Ciphertext Data
                // =========================================================================

                /// Ciphertext for AES-128: 69c4e0d86a7b0430d8cdb78070b4c55a
                extern const unsigned char AES128_CipherText[16];

                /// Ciphertext for AES-192: dda97ca4864cdfe06eaf70a0ec0d7191
                extern const unsigned char AES192_CipherText[16];

                /// Ciphertext for AES-256: 8ea2b7ca516745bfeafc49904b496089
                extern const unsigned char AES256_CipherText[16];

                /**
                 * @brief Get ciphertext by key size
                 * @param ks Key size
                 * @return Pointer to ciphertext data or nullptr if invalid
                 */
                const unsigned char* getCipherText(KeySize ks);

                // =========================================================================
                // Key Schedule Data (Expanded Keys)
                // =========================================================================

                /// AES-128 expanded key schedule (11 round keys, 176 bytes)
                extern const unsigned char AES128_KeyExpansion[176];

                /// AES-192 expanded key schedule (13 round keys, 208 bytes)
                extern const unsigned char AES192_KeyExpansion[208];

                /// AES-256 expanded key schedule (15 round keys, 240 bytes)
                extern const unsigned char AES256_KeyExpansion[240];

                /**
                 * @brief Get key schedule by key size
                 * @param ks Key size
                 * @return Pointer to key schedule data or nullptr if invalid
                 */
                const unsigned char* getKeyExpansion(KeySize ks);

                // =========================================================================
                // Test Vector Class
                // =========================================================================

                /**
                 * @brief Test vector for full cipher validation
                 *
                 * Provides plaintext, key, expected ciphertext, and key schedule
                 * for encryption/decryption.
                 */
                class TestVector : public TestVectorBase {
                private:
                    const unsigned char* input_;
                    const unsigned char* expectedOutput_;
                    const unsigned char* keyExpansion_;
                    size_t keyExpansionSize_;

                public:
                    /**
                     * @brief Construct cipher test vector
                     * @param ks Key size
                     * @param dir Direction (Encrypt or Decrypt)
                     */
                    TestVector(
                        KeySize ks,
                        Direction dir = Direction::Encrypt
                    );

                    // TestVectorBase interface implementation
                    const unsigned char* getInput() const override { return input_; }
                    const unsigned char* getExpectedOutput() const override { return expectedOutput_; }
                    size_t getDataSize() const override { return 16; } // Single block

                    // Key schedule accessors
                    const unsigned char* getKeyExpansion() const { return keyExpansion_; }
                    size_t getKeyExpansionSize() const { return keyExpansionSize_; }

                    // Convenience accessors
                    std::vector<unsigned char> getInputAsVector() const;
                    std::vector<unsigned char> getExpectedOutputAsVector() const;
                    std::vector<unsigned char> getKeyExpansionAsVector() const;
                };

                // =========================================================================
                // Factory Functions
                // =========================================================================

                /**
                 * @brief Create cipher test vector
                 * @param ks Key size
                 * @param dir Direction
                 * @return Unique pointer to test vector
                 */
                std::unique_ptr<TestVector> create(
                    KeySize ks,
                    Direction dir = Direction::Encrypt
                );

            } // namespace Cipher
        } // namespace FIPS197
    } // namespace AES
} // namespace TestVectors

#endif // TEST_VECTORS_FIPS197_CIPHER_HPP
