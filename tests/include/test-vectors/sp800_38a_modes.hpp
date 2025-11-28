/**
 * @file sp800_38a_modes.hpp
 * @brief NIST SP 800-38A Appendix F - Modes of Operation Test Vectors
 *
 * Contains official NIST test vectors for ECB, CBC, OFB, and CTR modes.
 * All modes share common plaintext but use different ciphertexts and
 * mode-specific parameters (IV, Counter).
 */

#ifndef TEST_VECTORS_SP800_38A_MODES_HPP
#define TEST_VECTORS_SP800_38A_MODES_HPP

#include "common.hpp"
#include <memory>

namespace TestVectors {
    namespace AES {
        namespace SP800_38A {

            // =========================================================================
            // Common Test Data
            // =========================================================================

            constexpr size_t kDataSize = 64; // 4 blocks

            /// Common plaintext (64 bytes = 4 blocks)
            extern const unsigned char kPlainText[kDataSize];

            /// Initialization Vector for CBC and OFB modes
            extern const unsigned char kInitializationVector[16];

            /// Initial Counter for CTR mode
            extern const unsigned char kInitialCounter[16];

            /**
             * @brief Get initialization vector
             * @return Pointer to IV data
             */
            const unsigned char* getIV();

            /**
             * @brief Get initial counter
             * @return Pointer to counter data
             */
            const unsigned char* getCounter();

            // =========================================================================
            // Base Test Vector Class
            // =========================================================================

            /**
             * @brief Base class for SP 800-38A mode test vectors
             *
             * Extends TestVectorBase with mode-specific information.
             */
            class ModeTestVectorBase : public TestVectorBase {
            protected:
                CipherMode mode_;
                const unsigned char* input_;
                const unsigned char* expectedOutput_;

            public:
                virtual ~ModeTestVectorBase() = default;

                // Additional query methods
                CipherMode getCipherMode() const { return mode_; }

                // TestVectorBase interface
                const std::vector<unsigned char> getInput() const override;
                const std::vector<unsigned char> getExpectedOutput() const override;
                size_t getDataSize() const override { return kDataSize; }
            };

            // =========================================================================
            // ECB Mode
            // =========================================================================

            namespace ECB {
                /// Ciphertext for AES-128 ECB
                extern const unsigned char AES128_CipherText[kDataSize];

                /// Ciphertext for AES-192 ECB
                extern const unsigned char AES192_CipherText[kDataSize];

                /// Ciphertext for AES-256 ECB
                extern const unsigned char AES256_CipherText[kDataSize];

                /**
                 * @brief Get ECB ciphertext by key size
                 * @param ks Key size
                 * @return Pointer to ciphertext or nullptr if invalid
                 */
                const unsigned char* getCipherText(KeySize ks);

                /**
                 * @brief ECB mode test vector
                 */
                class TestVector : public ModeTestVectorBase {
                public:
                    TestVector(
                        KeySize ks,
                        Direction dir = Direction::Encrypt
                    );
                };

                /**
                 * @brief Create ECB test vector
                 */
                std::unique_ptr<TestVector> create(
                    KeySize ks,
                    Direction dir = Direction::Encrypt
                );
            }

            // =========================================================================
            // CBC Mode
            // =========================================================================

            namespace CBC {
                /// Ciphertext for AES-128 CBC
                extern const unsigned char AES128_CipherText[kDataSize];

                /// Ciphertext for AES-192 CBC
                extern const unsigned char AES192_CipherText[kDataSize];

                /// Ciphertext for AES-256 CBC
                extern const unsigned char AES256_CipherText[kDataSize];

                /**
                 * @brief Get CBC ciphertext by key size
                 * @param ks Key size
                 * @return Pointer to ciphertext or nullptr if invalid
                 */
                const unsigned char* getCipherText(KeySize ks);

                /**
                 * @brief CBC mode test vector
                 */
                class TestVector : public ModeTestVectorBase {
                private:
                    const unsigned char* iv_;

                public:
                    TestVector(
                        KeySize ks,
                        Direction dir = Direction::Encrypt
                    );

                    const std::vector<unsigned char> getIV() const;
                };

                /**
                 * @brief Create CBC test vector
                 */
                std::unique_ptr<TestVector> create(
                    KeySize ks,
                    Direction dir = Direction::Encrypt
                );
            }

            // =========================================================================
            // OFB Mode
            // =========================================================================

            namespace OFB {
                /// Ciphertext for AES-128 OFB
                extern const unsigned char AES128_CipherText[kDataSize];

                /// Ciphertext for AES-192 OFB
                extern const unsigned char AES192_CipherText[kDataSize];

                /// Ciphertext for AES-256 OFB
                extern const unsigned char AES256_CipherText[kDataSize];

                /**
                 * @brief Get OFB ciphertext by key size
                 * @param ks Key size
                 * @return Pointer to ciphertext or nullptr if invalid
                 */
                const unsigned char* getCipherText(KeySize ks);

                /**
                 * @brief OFB mode test vector
                 */
                class TestVector : public ModeTestVectorBase {
                private:
                    const unsigned char* iv_;

                public:
                    TestVector(
                        KeySize ks,
                        Direction dir = Direction::Encrypt
                    );

                    const std::vector<unsigned char> getIV() const;
                };

                /**
                 * @brief Create OFB test vector
                 */
                std::unique_ptr<TestVector> create(
                    KeySize ks,
                    Direction dir = Direction::Encrypt
                );
            }

            // =========================================================================
            // CTR Mode
            // =========================================================================

            namespace CTR {
                /// Ciphertext for AES-128 CTR
                extern const unsigned char AES128_CipherText[kDataSize];

                /// Ciphertext for AES-192 CTR
                extern const unsigned char AES192_CipherText[kDataSize];

                /// Ciphertext for AES-256 CTR
                extern const unsigned char AES256_CipherText[kDataSize];

                /**
                 * @brief Get CTR ciphertext by key size
                 * @param ks Key size
                 * @return Pointer to ciphertext or nullptr if invalid
                 */
                const unsigned char* getCipherText(KeySize ks);

                /**
                 * @brief CTR mode test vector
                 */
                class TestVector : public ModeTestVectorBase {
                private:
                    const unsigned char* counter_;

                public:
                    TestVector(
                        KeySize ks,
                        Direction dir = Direction::Encrypt
                    );

                    const std::vector<unsigned char> getCounter() const;
                };

                /**
                 * @brief Create CTR test vector
                 */
                std::unique_ptr<TestVector> create(
                    KeySize ks,
                    Direction dir = Direction::Encrypt
                );
            }

            // =========================================================================
            // Generic Factory
            // =========================================================================

            /**
             * @brief Create test vector for any mode
             * @param ks Key size
             * @param mode Cipher mode
             * @param dir Direction
             * @return Unique pointer to mode-specific test vector (upcast to base)
             */
            std::unique_ptr<ModeTestVectorBase> create(
                KeySize ks,
                CipherMode mode,
                Direction dir = Direction::Encrypt
            );

        } // namespace SP800_38A
    } // namespace AES
} // namespace TestVectors

#endif // TEST_VECTORS_SP800_38A_MODES_HPP
