/*
 * Common AES Test Vectors and Definitions - Implementation File
 *
 * This file contains the implementations of functions declared in common_aes_vectors.hpp.
 */

#include "../include/common_aes_vectors.hpp"

namespace CommonAESVectors {

    // =============================================================================
    // Utility Function Implementations
    // =============================================================================

    size_t getKeyLengthBytes(KeylengthBits klb) {
        switch(klb) {
            case KeylengthBits::keylen128: return 16;
            case KeylengthBits::keylen192: return 24;
            case KeylengthBits::keylen256: return 32;
            default: return 0;
        }
    }

    const char* getKeylengthString(KeylengthBits keylen) {
        switch(keylen) {
            case KeylengthBits::keylen128: return "128";
            case KeylengthBits::keylen192: return "192";
            case KeylengthBits::keylen256: return "256";
            default: return "Unknown";
        }
    }

    const char* getOperationString(EncryptionOperationType op) {
        switch(op) {
            case EncryptionOperationType::Encryption: return "Encryption";
            case EncryptionOperationType::Decryption: return "Decryption";
            default: return "Unknown";
        }
    }

    const char* getVectorSourceString(VectorSource vs) {
        switch(vs) {
            case VectorSource::NIST_Official: return "NIST Official";
            case VectorSource::Stub_Sequential: return "Stub Sequential";
            case VectorSource::Stub_Zeros: return "Stub Zeros";
            case VectorSource::Stub_Ones: return "Stub Ones";
            case VectorSource::Stub_Alternating: return "Stub Alternating";
            default: return "Unknown";
        }
    }

    const unsigned char* retrieveKey(KeylengthBits kl) {
        switch(kl) {
            case KeylengthBits::keylen128: return key128;
            case KeylengthBits::keylen192: return key192;
            case KeylengthBits::keylen256: return key256;
            default: return nullptr;
        }
    }

    const unsigned char* retrieveStubKey(KeylengthBits kl, VectorSource vs) {
        // First handle by vector source type
        switch(vs) {
            case VectorSource::NIST_Official:
                return retrieveKey(kl); // Delegate to official keys

            case VectorSource::Stub_Sequential:
                switch(kl) {
                    case KeylengthBits::keylen128: return stub_key128_sequential;
                    case KeylengthBits::keylen192: return stub_key192_sequential;
                    case KeylengthBits::keylen256: return stub_key256_sequential;
                    default: return nullptr;
                }

                    case VectorSource::Stub_Zeros:
                        switch(kl) {
                            case KeylengthBits::keylen128: return stub_key128_zeros;
                            case KeylengthBits::keylen192: return stub_key192_zeros;
                            case KeylengthBits::keylen256: return stub_key256_zeros;
                            default: return nullptr;
                        }

                            case VectorSource::Stub_Ones:
                                switch(kl) {
                                    case KeylengthBits::keylen128: return stub_key128_ones;
                                    case KeylengthBits::keylen192: return stub_key192_ones;
                                    case KeylengthBits::keylen256: return stub_key256_ones;
                                    default: return nullptr;
                                }

                                    case VectorSource::Stub_Alternating:
                                        switch(kl) {
                                            case KeylengthBits::keylen128: return stub_key128_alternating;
                                            case KeylengthBits::keylen192: return stub_key192_alternating;
                                            case KeylengthBits::keylen256: return stub_key256_alternating;
                                            default: return nullptr;
                                        }

                                            default:
                                                return nullptr;
        }
    }

    // =============================================================================
    // ExampleBase Implementation
    // =============================================================================

    KeylengthBits ExampleBase::getKeylenBits() const {
        return this->keylenbits;
    }

    size_t ExampleBase::getKeylenBytes() const {
        switch(this->keylenbits) {
            case KeylengthBits::keylen128: return 16;
            case KeylengthBits::keylen192: return 24;
            case KeylengthBits::keylen256: return 32;
            default: return 0;
        }
    }

    const unsigned char* ExampleBase::getKey() const {
        return this->key;
    }

    std::vector<unsigned char> ExampleBase::getKeyAsVector() const {
        return std::vector<unsigned char>(this->key, this->key + this->getKeylenBytes());
    }

} // namespace CommonAESVectors
