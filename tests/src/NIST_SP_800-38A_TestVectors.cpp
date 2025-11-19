/*
 * NIST SP 800-38A Test Vectors - Implementation File
 *
 * This file contains the implementations for the NIST SP 800-38A test vectors
 * for ECB, CBC, OFB, and CTR modes.
 */

#include "../include/NIST_SP_800-38A_TestVectors.hpp"
#include <map>

namespace NISTSP800_38A_Examples {

    // =============================================================================
    // Utility Functions Implementation
    // =============================================================================

    const char* getModeString(OperationMode mode) {
        switch(mode) {
            case OperationMode::ECB: return "ECB";
            case OperationMode::CBC: return "CBC";
            case OperationMode::OFB: return "OFB";
            case OperationMode::CTR: return "CTR";
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
    // ExampleBase Implementation
    // =============================================================================

    CommonAESVectors::EncryptionOperationType ExampleBase::getOperationType() const {
        return this->operation;
    }

    OperationMode ExampleBase::getOperationMode() const {
        return this->mode;
    }

    const unsigned char* ExampleBase::getInput() const {
        return this->input;
    }

    std::vector<unsigned char> ExampleBase::getInputAsVector() const {
        return std::vector<unsigned char>(this->input, this->input + TEXT_SIZE);
    }

    const unsigned char* ExampleBase::getExpectedOutput() const {
        return this->expectedOutput;
    }

    std::vector<unsigned char> ExampleBase::getExpectedOutputAsVector() const {
        return std::vector<unsigned char>(this->expectedOutput, this->expectedOutput + TEXT_SIZE);
    }

    // =============================================================================
    // ECB Mode Implementation
    // =============================================================================

    namespace ECB_ns {

        const unsigned char* retrieveECBCiphertext(CommonAESVectors::KeylengthBits klb) {
            switch(klb) {
                case CommonAESVectors::KeylengthBits::keylen128: return ecb_aes128_ciphertext;
                case CommonAESVectors::KeylengthBits::keylen192: return ecb_aes192_ciphertext;
                case CommonAESVectors::KeylengthBits::keylen256: return ecb_aes256_ciphertext;
                default: return nullptr;
            }
        }

        Example::Example(CommonAESVectors::KeylengthBits klb, CommonAESVectors::EncryptionOperationType op) {
            this->keylenbits = klb;
            this->mode = OperationMode::ECB;
            this->operation = op;
            this->key = CommonAESVectors::retrieveKey(klb);

            switch(op) {
                case CommonAESVectors::EncryptionOperationType::Encryption:
                    this->input = commonPlaintext;
                    this->expectedOutput = retrieveECBCiphertext(klb);
                    break;
                case CommonAESVectors::EncryptionOperationType::Decryption:
                    this->input = retrieveECBCiphertext(klb);
                    this->expectedOutput = commonPlaintext;
                    break;
                default:
                    this->input = nullptr;
                    this->expectedOutput = nullptr;
                    break;
            }
        }

    } // namespace ECB_ns

    // =============================================================================
    // CBC Mode Implementation
    // =============================================================================

    namespace CBC_ns {

        const unsigned char* retrieveCBCCiphertext(CommonAESVectors::KeylengthBits klb) {
            switch(klb) {
                case CommonAESVectors::KeylengthBits::keylen128: return cbc_aes128_ciphertext;
                case CommonAESVectors::KeylengthBits::keylen192: return cbc_aes192_ciphertext;
                case CommonAESVectors::KeylengthBits::keylen256: return cbc_aes256_ciphertext;
                default: return nullptr;
            }
        }

        Example::Example(CommonAESVectors::KeylengthBits klb, CommonAESVectors::EncryptionOperationType op) {
            this->keylenbits = klb;
            this->mode = OperationMode::CBC;
            this->operation = op;
            this->key = CommonAESVectors::retrieveKey(klb);
            this->iv = initializationVector;

            switch(op) {
                case CommonAESVectors::EncryptionOperationType::Encryption:
                    this->input = commonPlaintext;
                    this->expectedOutput = retrieveCBCCiphertext(klb);
                    break;
                case CommonAESVectors::EncryptionOperationType::Decryption:
                    this->input = retrieveCBCCiphertext(klb);
                    this->expectedOutput = commonPlaintext;
                    break;
                default:
                    this->input = nullptr;
                    this->expectedOutput = nullptr;
                    break;
            }
        }

        const unsigned char* Example::getIV() const {
            return this->iv;
        }

    } // namespace CBC_ns

    // =============================================================================
    // OFB Mode Implementation
    // =============================================================================

    namespace OFB_ns {

        const unsigned char* retrieveOFBCiphertext(CommonAESVectors::KeylengthBits klb) {
            switch(klb) {
                case CommonAESVectors::KeylengthBits::keylen128: return ofb_aes128_ciphertext;
                case CommonAESVectors::KeylengthBits::keylen192: return ofb_aes192_ciphertext;
                case CommonAESVectors::KeylengthBits::keylen256: return ofb_aes256_ciphertext;
                default: return nullptr;
            }
        }

        Example::Example(CommonAESVectors::KeylengthBits klb, CommonAESVectors::EncryptionOperationType op) {
            this->keylenbits = klb;
            this->mode = OperationMode::OFB;
            this->operation = op;
            this->key = CommonAESVectors::retrieveKey(klb);
            this->iv = initializationVector;

            switch(op) {
                case CommonAESVectors::EncryptionOperationType::Encryption:
                    this->input = commonPlaintext;
                    this->expectedOutput = retrieveOFBCiphertext(klb);
                    break;
                case CommonAESVectors::EncryptionOperationType::Decryption:
                    this->input = retrieveOFBCiphertext(klb);
                    this->expectedOutput = commonPlaintext;
                    break;
                default:
                    this->input = nullptr;
                    this->expectedOutput = nullptr;
                    break;
            }
        }

        const unsigned char* Example::getIV() const {
            return this->iv;
        }

    } // namespace OFB_ns

    // =============================================================================
    // CTR Mode Implementation
    // =============================================================================

    namespace CTR_ns {

        const unsigned char* retrieveCTRCiphertext(CommonAESVectors::KeylengthBits klb) {
            switch(klb) {
                case CommonAESVectors::KeylengthBits::keylen128: return ctr_aes128_ciphertext;
                case CommonAESVectors::KeylengthBits::keylen192: return ctr_aes192_ciphertext;
                case CommonAESVectors::KeylengthBits::keylen256: return ctr_aes256_ciphertext;
                default: return nullptr;
            }
        }

        Example::Example(CommonAESVectors::KeylengthBits klb, CommonAESVectors::EncryptionOperationType op) {
            this->keylenbits = klb;
            this->mode = OperationMode::CTR;
            this->operation = op;
            this->key = CommonAESVectors::retrieveKey(klb);
            this->counter = initialCounter;

            switch(op) {
                case CommonAESVectors::EncryptionOperationType::Encryption:
                    this->input = commonPlaintext;
                    this->expectedOutput = retrieveCTRCiphertext(klb);
                    break;
                case CommonAESVectors::EncryptionOperationType::Decryption:
                    this->input = retrieveCTRCiphertext(klb);
                    this->expectedOutput = commonPlaintext;
                    break;
                default:
                    this->input = nullptr;
                    this->expectedOutput = nullptr;
                    break;
            }
        }

        const unsigned char* Example::getCounter() const {
            return this->counter;
        }

    } // namespace CTR_ns

    // =============================================================================
    // Factory Functions Implementation
    // =============================================================================

    std::unique_ptr<ExampleBase> makeExampleECB(CommonAESVectors::KeylengthBits klb) {
        return std::make_unique<ECB_ns::Example>(klb, CommonAESVectors::EncryptionOperationType::Encryption);
    }

    std::unique_ptr<ExampleBase> makeExampleCBC(CommonAESVectors::KeylengthBits klb) {
        return std::make_unique<CBC_ns::Example>(klb, CommonAESVectors::EncryptionOperationType::Encryption);
    }

    std::unique_ptr<ExampleBase> makeExampleOFB(CommonAESVectors::KeylengthBits klb) {
        return std::make_unique<OFB_ns::Example>(klb, CommonAESVectors::EncryptionOperationType::Encryption);
    }

    std::unique_ptr<ExampleBase> makeExampleCTR(CommonAESVectors::KeylengthBits klb) {
        return std::make_unique<CTR_ns::Example>(klb, CommonAESVectors::EncryptionOperationType::Encryption);
    }

    // The map that connects the enum to the factory function
    static const std::map<OperationMode, ExampleFactory> factoryMap = {
        { OperationMode::ECB, &makeExampleECB },
        { OperationMode::CBC, &makeExampleCBC },
        { OperationMode::OFB, &makeExampleOFB },
        { OperationMode::CTR, &makeExampleCTR }
    };

    /**
     * @brief Factory dispatcher using a map lookup.
     */
    std::unique_ptr<ExampleBase> createExample(CommonAESVectors::KeylengthBits klb, OperationMode mode) {
        auto it = factoryMap.find(mode);
        if (it != factoryMap.end()) {
            return it->second(klb);
        }
        return nullptr;
    }

} // namespace NISTSP800_38A_Examples
