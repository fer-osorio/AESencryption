/**
 * @file fips197_cipher.cpp
 * @brief Implementation of FIPS 197 Appendix B & C - Cipher Test Vectors
 */

#include "../../include/test-vectors/fips197_cipher.hpp"
#include "../../include/test-vectors/keys.hpp"

namespace TestVectors {
    namespace AES {
        namespace FIPS197 {
            namespace Cipher {

                // =========================================================================
                // Plaintext Data Implementation
                // =========================================================================

                const unsigned char kPlainText[16] = {
                    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
                };

                // =========================================================================
                // Ciphertext Data Implementation
                // =========================================================================

                const unsigned char AES128_CipherText[16] = {
                    0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
                    0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a
                };

                const unsigned char AES192_CipherText[16] = {
                    0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0,
                    0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91
                };

                const unsigned char AES256_CipherText[16] = {
                    0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
                    0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89
                };

                const unsigned char* getCipherText(KeySize ks) {
                    switch(ks) {
                        case KeySize::AES128: return AES128_CipherText;
                        case KeySize::AES192: return AES192_CipherText;
                        case KeySize::AES256: return AES256_CipherText;
                        default: return nullptr;
                    }
                }

                // =========================================================================
                // Test Vector Class Implementation
                // =========================================================================

                TestVector::TestVector(KeySize ks, Direction dir) {
                    keySize_ = ks;
                    direction_ = dir;
                    dataSource_ = DataSource::NIST_Official;
                    
                    // Use the FIPS197 Cipher keys (different from Key Expansion keys)
                    key_ = Keys::FIPS197_Cipher::get(ks);

                    switch(dir) {
                        case Direction::Encrypt:
                            input_ = kPlainText;
                            expectedOutput_ = getCipherText(ks);
                            break;
                        case Direction::Decrypt:
                            input_ = getCipherText(ks);
                            expectedOutput_ = kPlainText;
                            break;
                    }
                }

                std::vector<unsigned char> TestVector::getInputAsVector() const {
                    return std::vector<unsigned char>(input_, input_ + 16);
                }

                std::vector<unsigned char> TestVector::getExpectedOutputAsVector() const {
                    return std::vector<unsigned char>(expectedOutput_, expectedOutput_ + 16);
                }

                // =========================================================================
                // Factory Functions Implementation
                // =========================================================================

                std::unique_ptr<TestVector> create(KeySize ks, Direction dir) {
                    return std::make_unique<TestVector>(ks, dir);
                }

            } // namespace Cipher
        } // namespace FIPS197
    } // namespace AES
} // namespace TestVectors
