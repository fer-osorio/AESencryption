/**
 * @file fips197_key_expansion.hpp
 * @brief FIPS 197 Appendix A - Key Expansion Test Vectors
 *
 * Contains official NIST test vectors for validating the AES key schedule
 * generation algorithm for all three key sizes (128, 192, 256 bits).
 */

#ifndef TEST_VECTORS_FIPS197_KEY_EXPANSION_HPP
#define TEST_VECTORS_FIPS197_KEY_EXPANSION_HPP

#include "common.hpp"
#include <memory>

namespace TestVectors {
    namespace AES {
        namespace FIPS197 {
            namespace KeyExpansion {

                // =========================================================================
                // Expanded Key Data
                // =========================================================================

                /// Expanded key for AES-128 (176 bytes = 44 words × 4 bytes)
                extern const unsigned char AES128_Expanded[176];

                /// Expanded key for AES-192 (208 bytes = 52 words × 4 bytes)
                extern const unsigned char AES192_Expanded[208];

                /// Expanded key for AES-256 (240 bytes = 60 words × 4 bytes)
                extern const unsigned char AES256_Expanded[240];

                /**
                 * @brief Get expanded key by size
                 * @param ks Key size
                 * @return Pointer to expanded key data or nullptr if invalid
                 */
                const unsigned char* getExpandedKey(KeySize ks);

                // =========================================================================
                // Test Vector Class
                // =========================================================================

                /**
                 * @brief Test vector for key expansion validation
                 *
                 * Provides both the input key and expected expanded key schedule.
                 */
                class TestVector : public TestVectorBase {
                private:
                    const unsigned char* expectedExpansion_;

                public:
                    /**
                     * @brief Construct key expansion test vector
                     * @param ks Key size
                     */
                    explicit TestVector(KeySize ks);

                    // TestVectorBase interface implementation
                    const std::vector<unsigned char> getInput() const override;
                    const std::vector<unsigned char> getExpectedOutput() const override;
                    size_t getDataSize() const override { return getExpandedKeySizeBytes(keySize_); }

                    // Convenience accessors
                    const std::vector<unsigned char> getExpectedExpansion()const ;
                };

                // =========================================================================
                // Factory Functions
                // =========================================================================

                /**
                 * @brief Create key expansion test vector
                 * @param ks Key size
                 * @return Unique pointer to test vector
                 */
                std::unique_ptr<TestVector> create(KeySize ks);

            } // namespace KeyExpansion
        } // namespace FIPS197
    } // namespace AES
} // namespace TestVectors

#endif // TEST_VECTORS_FIPS197_KEY_EXPANSION_HPP
