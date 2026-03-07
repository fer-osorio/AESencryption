/**
 * @file keys.hpp
 * @brief Centralized storage for AES test vector keys
 *
 * This file contains all keys used in FIPS 197 and SP 800-38A test vectors,
 * organized by source (NIST official vs stub/mock data).
 */

#ifndef TEST_VECTORS_KEYS_HPP
#define TEST_VECTORS_KEYS_HPP

#include "common.hpp"

namespace TestVectors {
    namespace AES {
        namespace Keys {

            // =========================================================================
            // NIST Official Keys
            // =========================================================================

            /**
             * @brief Official NIST keys shared by multiple standards
             *
             * These keys appear in both FIPS 197 Appendix A (Key Expansion) and
             * SP 800-38A Appendix F (Modes of Operation).
             */
            namespace NIST {
                /// AES-128 key: 2b7e151628aed2a6abf7158809cf4f3c
                extern const unsigned char AES128[16];

                /// AES-192 key: 8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b
                extern const unsigned char AES192[24];

                /// AES-256 key: 603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
                extern const unsigned char AES256[32];

                /**
                 * @brief Get NIST official key by size
                 * @param ks Key size
                 * @return Pointer to key data or nullptr if invalid
                 */
                const unsigned char* get(KeySize ks);
            }

            /**
             * @brief Keys specific to FIPS 197 Appendix B (Cipher Example)
             *
             * These are different from the Key Expansion keys and use sequential bytes.
             */
            namespace FIPS197_Cipher {
                /// AES-128 key: 000102030405060708090a0b0c0d0e0f
                extern const unsigned char AES128[16];

                /// AES-192 key: 000102030405060708090a0b0c0d0e0f1011121314151617
                extern const unsigned char AES192[24];

                /// AES-256 key: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
                extern const unsigned char AES256[32];

                /**
                 * @brief Get FIPS 197 Cipher example key by size
                 * @param ks Key size
                 * @return Pointer to key data or nullptr if invalid
                 */
                const unsigned char* get(KeySize ks);
            }

            /**
             * @brief Stub keys for testing infrastructure (non-cryptographic)
             *
             * These keys are NOT cryptographically valid but useful for:
             * - Debugging (sequential pattern is easy to trace)
             * - Edge case testing (all zeros, all ones)
             * - Visual inspection of data flow
             */
            namespace Stub {
                namespace Sequential {
                    extern const unsigned char AES128[16];
                    extern const unsigned char AES192[24];
                    extern const unsigned char AES256[32];
                }

                namespace Zeros {
                    extern const unsigned char AES128[16];
                    extern const unsigned char AES192[24];
                    extern const unsigned char AES256[32];
                }

                namespace Ones {
                    extern const unsigned char AES128[16];
                    extern const unsigned char AES192[24];
                    extern const unsigned char AES256[32];
                }

                /**
                 * @brief Get stub key by size and pattern
                 * @param ks Key size
                 * @param ds Data source (must be a Stub_* variant)
                 * @return Pointer to key data or nullptr if invalid
                 */
                const unsigned char* get(KeySize ks, DataSource ds);
            }

            // =========================================================================
            // Unified Getter
            // =========================================================================

            /**
             * @brief Get any key by size and source
             * @param ks Key size
             * @param source Data source (NIST or Stub variants)
             * @param useCipherKeys If true, use FIPS197_Cipher keys instead of standard NIST keys
             * @return Pointer to key data or nullptr if invalid combination
             */
            const unsigned char* get(
                KeySize ks,
                DataSource source = DataSource::NIST_Official,
                bool useCipherKeys = false
            );

        } // namespace Keys
    } // namespace AES
} // namespace TestVectors

#endif // TEST_VECTORS_KEYS_HPP
