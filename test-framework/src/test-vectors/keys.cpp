/**
 * @file keys.cpp
 * @brief Implementation of key management functions
 */

#include "../../include/test-vectors/keys.hpp"

namespace TestVectors {
    namespace AES {
        namespace Keys {

            // =========================================================================
            // NIST Official Keys Implementation
            // =========================================================================

            namespace NIST {
                // AES-128 key: 2b7e151628aed2a6abf7158809cf4f3c
                const unsigned char AES128[16] = {
                    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
                };

                // AES-192 key: 8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b
                const unsigned char AES192[24] = {
                    0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
                    0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
                    0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
                };

                // AES-256 key: 603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
                const unsigned char AES256[32] = {
                    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
                    0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
                    0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
                };

                const unsigned char* get(KeySize ks) {
                    switch(ks) {
                        case KeySize::AES128: return AES128;
                        case KeySize::AES192: return AES192;
                        case KeySize::AES256: return AES256;
                        default: return nullptr;
                    }
                }
            } // namespace NIST

            // =========================================================================
            // FIPS197 Cipher Keys Implementation
            // =========================================================================

            namespace FIPS197_Cipher {
                // AES-128 key: 000102030405060708090a0b0c0d0e0f
                const unsigned char AES128[16] = {
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
                };

                // AES-192 key: 000102030405060708090a0b0c0d0e0f1011121314151617
                const unsigned char AES192[24] = {
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
                };

                // AES-256 key: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
                const unsigned char AES256[32] = {
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
                };

                const unsigned char* get(KeySize ks) {
                    switch(ks) {
                        case KeySize::AES128: return AES128;
                        case KeySize::AES192: return AES192;
                        case KeySize::AES256: return AES256;
                        default: return nullptr;
                    }
                }
            } // namespace FIPS197_Cipher

            // =========================================================================
            // Stub Keys Implementation
            // =========================================================================

            namespace Stub {
                namespace Sequential {
                    // Sequential pattern: 00 01 02 ... for each key size
                    const unsigned char AES128[16] = {
                        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
                    };

                    const unsigned char AES192[24] = {
                        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
                    };

                    const unsigned char AES256[32] = {
                        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
                    };
                } // namespace Sequential

                namespace Zeros {
                    // All zeros
                    const unsigned char AES128[16] = {0};
                    const unsigned char AES192[24] = {0};
                    const unsigned char AES256[32] = {0};
                } // namespace Zeros

                namespace Ones {
                    // All ones (0xFF)
                    const unsigned char AES128[16] = {
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
                    };
                    const unsigned char AES192[24] = {
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
                    };
                    const unsigned char AES256[32] = {
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
                    };
                } // namespace Ones

                const unsigned char* get(KeySize ks, DataSource ds) {
                    switch(ds) {
                        case DataSource::Stub_Sequential:
                            switch(ks) {
                                case KeySize::AES128: return Sequential::AES128;
                                case KeySize::AES192: return Sequential::AES192;
                                case KeySize::AES256: return Sequential::AES256;
                                default: return nullptr;
                            }
                        case DataSource::Stub_Zeros:
                            switch(ks) {
                                case KeySize::AES128: return Zeros::AES128;
                                case KeySize::AES192: return Zeros::AES192;
                                case KeySize::AES256: return Zeros::AES256;
                                default: return nullptr;
                            }
                        case DataSource::Stub_Ones:
                            switch(ks) {
                                case KeySize::AES128: return Ones::AES128;
                                case KeySize::AES192: return Ones::AES192;
                                case KeySize::AES256: return Ones::AES256;
                                default: return nullptr;
                            }
                        default:
                            return nullptr;
                    }
                }
            } // namespace Stub

            // =========================================================================
            // Unified Getter Implementation
            // =========================================================================

            const unsigned char* get(KeySize ks, DataSource source, bool useCipherKeys) {
                switch(source) {
                    case DataSource::NIST_Official:
                        if (useCipherKeys) {
                            return FIPS197_Cipher::get(ks);
                        } else {
                            return NIST::get(ks);
                        }
                    case DataSource::Stub_Sequential:
                    case DataSource::Stub_Zeros:
                    case DataSource::Stub_Ones:
                        return Stub::get(ks, source);
                    default:
                        return nullptr;
                }
            }

        } // namespace Keys
    } // namespace AES
} // namespace TestVectors
