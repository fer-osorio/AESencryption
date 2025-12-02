/**
 * @file stub_data.hpp
 * @brief Stub/mock data for testing AES implementation infrastructure
 *
 * This file contains non-cryptographic test data useful for:
 * - Unit testing individual components
 * - Debugging data flow
 * - Visual verification of transformations
 * - Edge case testing
 *
 * @warning These are NOT valid cryptographic test vectors!
 */

#ifndef TEST_VECTORS_STUB_DATA_HPP
#define TEST_VECTORS_STUB_DATA_HPP

#include "common.hpp"

namespace TestVectors {
    namespace AES {
        namespace Stub {

            // =========================================================================
            // Stub Key Expansions (NOT cryptographically correct!)
            // =========================================================================

            namespace KeyExpansion {
                namespace Sequential {
                    /// Mock expanded key for AES-128 (176 bytes, 11 round keys)
                    extern const unsigned char AES128[176];

                    /// Mock expanded key for AES-192 (208 bytes, 13 round keys)
                    extern const unsigned char AES192[208];

                    /// Mock expanded key for AES-256 (240 bytes, 15 round keys)
                    extern const unsigned char AES256[240];
                }

                namespace Zeros {
                    extern const unsigned char AES128[176];
                    extern const unsigned char AES192[208];
                    extern const unsigned char AES256[240];
                }

                namespace Ones {
                    extern const unsigned char AES128[176];
                    extern const unsigned char AES192[208];
                    extern const unsigned char AES256[240];
                }

                /**
                 * @brief Get stub key expansion by size and pattern
                 * @param ks Key size
                 * @param ds Data source pattern
                 * @return Pointer to expanded key data or nullptr if invalid
                 */
                const unsigned char* get(KeySize ks, DataSource ds);
            }

            // =========================================================================
            // Stub Plaintext/Ciphertext Blocks
            // =========================================================================

            namespace Block {
                /// 16-byte block of zeros
                extern const unsigned char Zeros[16];

                /// 16-byte sequential pattern: 00 01 02 ... 0e 0f
                extern const unsigned char Sequential[16];

                /// 16-byte block of ones (0xFF)
                extern const unsigned char Ones[16];

                /**
                 * @brief Get stub block by pattern
                 * @param ds Data source pattern
                 * @return Pointer to block data or nullptr if invalid
                 */
                const unsigned char* get(DataSource ds);
            }

            // =========================================================================
            // Stub IVs and Counters
            // =========================================================================

            namespace IV {
                extern const unsigned char Zeros[16];
                extern const unsigned char Sequential[16];
                extern const unsigned char Ones[16];

                const unsigned char* get(DataSource ds);
            }

            namespace Counter {
                extern const unsigned char Zeros[16];
                extern const unsigned char Sequential[16];
                extern const unsigned char Ones[16];

                const unsigned char* get(DataSource ds);
            }

        } // namespace Stub
    } // namespace AES
} // namespace TestVectors

#endif // TEST_VECTORS_STUB_DATA_HPP
