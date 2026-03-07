/**
 * @file common.cpp
 * @brief Implementation of common definitions and utility functions
 */

#include "../../include/test-vectors/common.hpp"

namespace TestVectors {
    namespace AES {

        // =========================================================================
        // Utility Function Implementations
        // =========================================================================

        size_t getKeySizeBytes(KeySize ks) {
            switch(ks) {
                case KeySize::AES128: return 16;
                case KeySize::AES192: return 24;
                case KeySize::AES256: return 32;
                default: return 0;
            }
        }

        const char* getKeySizeString(KeySize ks) {
            switch(ks) {
                case KeySize::AES128: return "128";
                case KeySize::AES192: return "192";
                case KeySize::AES256: return "256";
                default: return "Unknown";
            }
        }

        const char* getDirectionString(Direction dir) {
            switch(dir) {
                case Direction::Encrypt: return "Encrypt";
                case Direction::Decrypt: return "Decrypt";
                default: return "Unknown";
            }
        }

        const char* getDataSourceString(DataSource ds) {
            switch(ds) {
                case DataSource::NIST_Official: return "NIST Official";
                case DataSource::Stub_Sequential: return "Stub Sequential";
                case DataSource::Stub_Zeros: return "Stub Zeros";
                case DataSource::Stub_Ones: return "Stub Ones";
                default: return "Unknown";
            }
        }

        const char* getCipherModeString(CipherMode mode) {
            switch(mode) {
                case CipherMode::ECB: return "ECB";
                case CipherMode::CBC: return "CBC";
                case CipherMode::OFB: return "OFB";
                case CipherMode::CTR: return "CTR";
                default: return "Unknown";
            }
        }

        unsigned int getNumRounds(KeySize ks) {
            switch(ks) {
                case KeySize::AES128: return 10;
                case KeySize::AES192: return 12;
                case KeySize::AES256: return 14;
                default: return 0;
            }
        }

        size_t getExpandedKeySizeBytes(KeySize ks) {
            switch(ks) {
                case KeySize::AES128: return 176;  // 11 rounds * 16 bytes
                case KeySize::AES192: return 208;  // 13 rounds * 16 bytes
                case KeySize::AES256: return 240;  // 15 rounds * 16 bytes
                default: return 0;
            }
        }

        // =========================================================================
        // TestVectorBase Implementation
        // =========================================================================

        std::vector<unsigned char> TestVectorBase::getKey() const {
            if (key_ == nullptr) {
                return std::vector<unsigned char>();
            }
            return std::vector<unsigned char>(key_, key_ + getKeySizeBytes());
        }

    } // namespace AES
} // namespace TestVectors
