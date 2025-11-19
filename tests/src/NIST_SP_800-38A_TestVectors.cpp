/*
 * NIST SP 800-38A Test Vectors - Implementation File
 *
 * This file contains the implementations for the NIST SP 800-38A test vectors
 * for ECB, CBC, OFB, and CTR modes.
 */

#include "../include/NIST_SP_800-38A_TestVectors.hpp"
#include <map>

namespace SP800_38A {

    // =============================================================================
    // Utility Functions Implementation
    // =============================================================================

    const char* getModeString(CipherMode cm) {
        switch(cm) {
            case CipherMode::ECB: return "ECB";
            case CipherMode::CBC: return "CBC";
            case CipherMode::OFB: return "OFB";
            case CipherMode::CTR: return "CTR";
            default: return "Unknown";
        }
    }

    const unsigned char* getInitializationVector() {
        return initializationVector;
    }

    std::vector<unsigned char> getInitializationVectorAsStdVector() {
        return std::vector<unsigned char>(initializationVector, initializationVector + INITIALIZATION_VECTOR_SIZE);
    }

    const unsigned char* getInitialCounter() {
        return initialCounter;
    }

    std::vector<unsigned char> getInitialCounterAsStdVector() {
        return std::vector<unsigned char>(initialCounter, initialCounter + COUNTER_SIZE);
    }

    // =============================================================================
    // TestVectorBase Implementation
    // =============================================================================

    Common::Direction TestVectorBase::getDirection() const {
        return this->dir;
    }

    CipherMode TestVectorBase::getCipherMode() const {
        return this->cm;
    }

    const unsigned char* TestVectorBase::getInput() const {
        return this->input;
    }

    std::vector<unsigned char> TestVectorBase::getInputAsVector() const {
        return std::vector<unsigned char>(this->input, this->input + TEXT_SIZE);
    }

    const unsigned char* TestVectorBase::getExpectedOutput() const {
        return this->expectedOutput;
    }

    std::vector<unsigned char> TestVectorBase::getExpectedOutputAsVector() const {
        return std::vector<unsigned char>(this->expectedOutput, this->expectedOutput + TEXT_SIZE);
    }

    // =============================================================================
    // ECB Mode Implementation
    // =============================================================================

    namespace ECB {

        const unsigned char* getECBCiphertext(Common::KeySize ks) {
            switch(ks) {
                case Common::KeySize::AES128: return ecb_aes128_ciphertext;
                case Common::KeySize::AES192: return ecb_aes192_ciphertext;
                case Common::KeySize::AES256: return ecb_aes256_ciphertext;
                default: return nullptr;
            }
        }

        TestVector::TestVector(Common::KeySize ks, Common::Direction op) {
            this->keySize = ks;
            this->cm = CipherMode::ECB;
            this->dir = op;
            this->key = Common::getKey(ks);

            switch(op) {
                case Common::Direction::Encryption:
                    this->input = commonPlaintext;
                    this->expectedOutput = getECBCiphertext(ks);
                    break;
                case Common::Direction::Decryption:
                    this->input = getECBCiphertext(ks);
                    this->expectedOutput = commonPlaintext;
                    break;
                default:
                    this->input = nullptr;
                    this->expectedOutput = nullptr;
                    break;
            }
        }

    } // namespace ECB

    // =============================================================================
    // CBC Mode Implementation
    // =============================================================================

    namespace CBC {

        const unsigned char* getCBCCiphertext(Common::KeySize ks) {
            switch(ks) {
                case Common::KeySize::AES128: return cbc_aes128_ciphertext;
                case Common::KeySize::AES192: return cbc_aes192_ciphertext;
                case Common::KeySize::AES256: return cbc_aes256_ciphertext;
                default: return nullptr;
            }
        }

        TestVector::TestVector(Common::KeySize ks, Common::Direction op) {
            this->keySize = ks;
            this->cm = CipherMode::CBC;
            this->dir = op;
            this->key = Common::getKey(ks);
            this->iv = initializationVector;

            switch(op) {
                case Common::Direction::Encryption:
                    this->input = commonPlaintext;
                    this->expectedOutput = getCBCCiphertext(ks);
                    break;
                case Common::Direction::Decryption:
                    this->input = getCBCCiphertext(ks);
                    this->expectedOutput = commonPlaintext;
                    break;
                default:
                    this->input = nullptr;
                    this->expectedOutput = nullptr;
                    break;
            }
        }

        const unsigned char* TestVector::getIV() const {
            return this->iv;
        }

    } // namespace CBC

    // =============================================================================
    // OFB Mode Implementation
    // =============================================================================

    namespace OFB {

        const unsigned char* getOFBCiphertext(Common::KeySize ks) {
            switch(ks) {
                case Common::KeySize::AES128: return ofb_aes128_ciphertext;
                case Common::KeySize::AES192: return ofb_aes192_ciphertext;
                case Common::KeySize::AES256: return ofb_aes256_ciphertext;
                default: return nullptr;
            }
        }

        TestVector::TestVector(Common::KeySize ks, Common::Direction op) {
            this->keySize = ks;
            this->cm = CipherMode::OFB;
            this->dir = op;
            this->key = Common::getKey(ks);
            this->iv = initializationVector;

            switch(op) {
                case Common::Direction::Encryption:
                    this->input = commonPlaintext;
                    this->expectedOutput = getOFBCiphertext(ks);
                    break;
                case Common::Direction::Decryption:
                    this->input = getOFBCiphertext(ks);
                    this->expectedOutput = commonPlaintext;
                    break;
                default:
                    this->input = nullptr;
                    this->expectedOutput = nullptr;
                    break;
            }
        }

        const unsigned char* TestVector::getIV() const {
            return this->iv;
        }

    } // namespace OFB

    // =============================================================================
    // CTR Mode Implementation
    // =============================================================================

    namespace CTR {

        const unsigned char* getCTRCiphertext(Common::KeySize ks) {
            switch(ks) {
                case Common::KeySize::AES128: return ctr_aes128_ciphertext;
                case Common::KeySize::AES192: return ctr_aes192_ciphertext;
                case Common::KeySize::AES256: return ctr_aes256_ciphertext;
                default: return nullptr;
            }
        }

        TestVector::TestVector(Common::KeySize ks, Common::Direction op) {
            this->keySize = ks;
            this->cm = CipherMode::CTR;
            this->dir = op;
            this->key = Common::getKey(ks);
            this->counter = initialCounter;

            switch(op) {
                case Common::Direction::Encryption:
                    this->input = commonPlaintext;
                    this->expectedOutput = getCTRCiphertext(ks);
                    break;
                case Common::Direction::Decryption:
                    this->input = getCTRCiphertext(ks);
                    this->expectedOutput = commonPlaintext;
                    break;
                default:
                    this->input = nullptr;
                    this->expectedOutput = nullptr;
                    break;
            }
        }

        const unsigned char* TestVector::getCounter() const {
            return this->counter;
        }

    } // namespace CTR

    // =============================================================================
    // Factory Functions Implementation
    // =============================================================================

    std::unique_ptr<TestVectorBase> makeTestVectorECB(Common::KeySize ks) {
        return std::make_unique<ECB::TestVector>(ks, Common::Direction::Encryption);
    }

    std::unique_ptr<TestVectorBase> makeTestVectorCBC(Common::KeySize ks) {
        return std::make_unique<CBC::TestVector>(ks, Common::Direction::Encryption);
    }

    std::unique_ptr<TestVectorBase> makeTestVectorOFB(Common::KeySize ks) {
        return std::make_unique<OFB::TestVector>(ks, Common::Direction::Encryption);
    }

    std::unique_ptr<TestVectorBase> makeTestVectorCTR(Common::KeySize ks) {
        return std::make_unique<CTR::TestVector>(ks, Common::Direction::Encryption);
    }

    // The map that connects the enum to the factory function
    static const std::map<CipherMode, TestVectorFactory> factoryMap = {
        { CipherMode::ECB, &makeTestVectorECB },
        { CipherMode::CBC, &makeTestVectorCBC },
        { CipherMode::OFB, &makeTestVectorOFB },
        { CipherMode::CTR, &makeTestVectorCTR }
    };

    /**
     * @brief Factory dispatcher using a map lookup.
     */
    std::unique_ptr<TestVectorBase> createTestVector(Common::KeySize ks, CipherMode cm) {
        auto it = factoryMap.find(cm);
        if (it != factoryMap.end()) {
            return it->second(ks);
        }
        return nullptr;
    }

} // namespace SP800_38A
