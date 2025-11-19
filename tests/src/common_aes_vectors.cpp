/*
 * Common AES Test Vectors and Definitions - Implementation File
 *
 * This file contains the implementations of functions declared in common_aes_vectors.hpp.
 */

#include "../include/common_aes_vectors.hpp"

namespace Common {

    // =============================================================================
    // Utility Function Implementations
    // =============================================================================

    size_t getKeySizeBytes(KeySize keysz) {
        switch(keysz) {
            case KeySize::keylen128: return 16;
            case KeySize::keylen192: return 24;
            case KeySize::keylen256: return 32;
            default: return 0;
        }
    }

    const char* getKeySizeString(KeySize keysz) {
        switch(keysz) {
            case KeySize::keylen128: return "128";
            case KeySize::keylen192: return "192";
            case KeySize::keylen256: return "256";
            default: return "Unknown";
        }
    }

    const char* getDirectionString(Direction dir) {
        switch(dir) {
            case Direction::Encryption: return "Encryption";
            case Direction::Decryption: return "Decryption";
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

    const unsigned char* getKey(KeySize keysz) {
        switch(keysz) {
            case KeySize::keylen128: return key128;
            case KeySize::keylen192: return key192;
            case KeySize::keylen256: return key256;
            default: return nullptr;
        }
    }

    const unsigned char* getStubKey(KeySize keysz, VectorSource vs) {
        // First handle by vector source type
        switch(vs) {
            case VectorSource::NIST_Official:
                return getKey(keysz); // Delegate to official keys

            case VectorSource::Stub_Sequential:
                switch(keysz) {
                    case KeySize::keylen128: return stub_key128_sequential;
                    case KeySize::keylen192: return stub_key192_sequential;
                    case KeySize::keylen256: return stub_key256_sequential;
                    default: return nullptr;
                }

                    case VectorSource::Stub_Zeros:
                        switch(keysz) {
                            case KeySize::keylen128: return stub_key128_zeros;
                            case KeySize::keylen192: return stub_key192_zeros;
                            case KeySize::keylen256: return stub_key256_zeros;
                            default: return nullptr;
                        }

                            case VectorSource::Stub_Ones:
                                switch(keysz) {
                                    case KeySize::keylen128: return stub_key128_ones;
                                    case KeySize::keylen192: return stub_key192_ones;
                                    case KeySize::keylen256: return stub_key256_ones;
                                    default: return nullptr;
                                }

                                    case VectorSource::Stub_Alternating:
                                        switch(keysz) {
                                            case KeySize::keylen128: return stub_key128_alternating;
                                            case KeySize::keylen192: return stub_key192_alternating;
                                            case KeySize::keylen256: return stub_key256_alternating;
                                            default: return nullptr;
                                        }

                                            default:
                                                return nullptr;
        }
    }

    // =============================================================================
    // TestVectorBase Implementation
    // =============================================================================

    KeySize TestVectorBase::getKeySize() const {
        return this->keysz;
    }

    size_t TestVectorBase::getKeySizeBytes() const {
        switch(this->keysz) {
            case KeySize::keylen128: return 16;
            case KeySize::keylen192: return 24;
            case KeySize::keylen256: return 32;
            default: return 0;
        }
    }

    const unsigned char* TestVectorBase::getKey() const {
        return this->key;
    }

    std::vector<unsigned char> TestVectorBase::getKeyAsVector() const {
        return std::vector<unsigned char>(this->key, this->key + this->getKeySizeBytes());
    }

} // namespace Common
