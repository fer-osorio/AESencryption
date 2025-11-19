/*
 * AES Key Expansion and Cipher Examples - FIPS 197 Standard Reference - Implementation File
 *
 * This file contains the implementations for the FIPS 197 test vectors
 * for Key Expansion and Cipher examples.
 */

#include "../include/NIST_FIPS197_TestVectors.hpp"

namespace FIPS197 {

    // =============================================================================
    // Appendix A: Key Expansion Examples Implementation
    // =============================================================================

    namespace KeyExpansion {

        const unsigned char* getKeyExpansion(Common::KeySize ks) {
            switch (ks) {
                case Common::KeySize::AES128: return key128_expanded;
                case Common::KeySize::AES192: return key192_expanded;
                case Common::KeySize::AES256: return key256_expanded;
                default: return nullptr;
            }
        }

        TestVector::TestVector(Common::KeySize ks) {
            this->keySize = ks;
            // Uses the key retrieval function from the common header
            this->key = Common::getKey(ks);
            this->expectedKeyExpansion = getKeyExpansion(ks);
        }

        const unsigned char* TestVector::getExpectedKeyExpansion() const {
            return this->expectedKeyExpansion;
        }

    } // namespace KeyExpansion

    // =============================================================================
    // Appendix B: Cipher Example Implementation
    // =============================================================================

    namespace Encryption {

        // This function is local to this namespace and uses the local keys defined in the header.
        const unsigned char* getKey(Common::KeySize ks) {
            switch (ks) {
                case Common::KeySize::AES128: return key128;
                case Common::KeySize::AES192: return key192;
                case Common::KeySize::AES256: return key256;
                default: return nullptr;
            }
        }

        const unsigned char* getCipherText(Common::KeySize ks) {
            switch (ks) {
                case Common::KeySize::AES128: return cipherTextKey128;
                case Common::KeySize::AES192: return cipherTextKey192;
                case Common::KeySize::AES256: return cipherTextKey256;
                default: return nullptr;
            }
        }

        TestVector::TestVector(Common::KeySize ks, Common::Direction dir) {
            this->dir_ = dir;
            this->keySize = ks;
            this->key = Encryption::getKey(ks); // Uses the local getKey function

            switch (dir) {
                case Common::Direction::Encryption:
                    this->input = plainText;
                    this->expectedOutput = getCipherText(ks);
                    break;
                case Common::Direction::Decryption:
                    this->input = getCipherText(ks);
                    this->expectedOutput = plainText;
                    break;
                default:
                    this->input = nullptr;
                    this->expectedOutput = nullptr;
                    break;
            }
        }

        const unsigned char* TestVector::getInput() const {
            return this->input;
        }

        const unsigned char* TestVector::getExpectedOutput() const {
            return this->expectedOutput;
        }

    } // namespace Encryption

} // namespace FIPS197
