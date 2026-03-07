/**
 * @file common.hpp
 * @brief Common definitions, enumerations, and base classes for AES test vectors
 *
 * This file provides the foundational types and interfaces used across all
 * AES test vector implementations (FIPS 197 and SP 800-38A).
 */

#ifndef TEST_VECTORS_COMMON_HPP
#define TEST_VECTORS_COMMON_HPP

#include <cstddef>
#include <vector>

namespace TestVectors {
    namespace AES {

        // =========================================================================
        // Enumerations
        // =========================================================================

        /**
         * @brief Standard AES key sizes in bits
         */
        enum class KeySize {
            AES128 = 128,
            AES192 = 192,
            AES256 = 256,
            Unknown = 0
        };

        /**
         * @brief Cryptographic operation direction
         */
        enum class Direction {
            Encrypt,
            Decrypt
        };

        /**
         * @brief Source of test vector data
         */
        enum class DataSource {
            NIST_Official,      ///< Official NIST test vectors
            Stub_Sequential,    ///< Sequential bytes for debugging (0x00, 0x01, ...)
            Stub_Zeros,         ///< All zeros for edge case testing
            Stub_Ones           ///< All ones (0xFF) for bit manipulation testing
        };

        /**
         * @brief Cipher modes of operation (SP 800-38A)
         */
        enum class CipherMode {
            ECB,    ///< Electronic Codebook
            CBC,    ///< Cipher Block Chaining
            OFB,    ///< Output Feedback
            CTR,    ///< Counter
            Unknown
        };

        // =========================================================================
        // Utility Functions
        // =========================================================================

        /**
         * @brief Get key size in bytes
         * @param ks KeySize enumeration value
         * @return Size in bytes (16, 24, or 32) or 0 for Unknown
         */
        size_t getKeySizeBytes(KeySize ks);

        /**
         * @brief Get string representation of key size
         * @param ks KeySize enumeration value
         * @return String like "128", "192", "256", or "Unknown"
         */
        const char* getKeySizeString(KeySize ks);

        /**
         * @brief Get string representation of direction
         * @param dir Direction enumeration value
         * @return "Encrypt" or "Decrypt"
         */
        const char* getDirectionString(Direction dir);

        /**
         * @brief Get string representation of data source
         * @param ds DataSource enumeration value
         * @return Descriptive string of the data source
         */
        const char* getDataSourceString(DataSource ds);

        /**
         * @brief Get string representation of cipher mode
         * @param mode CipherMode enumeration value
         * @return "ECB", "CBC", "OFB", "CTR", or "Unknown"
         */
        const char* getCipherModeString(CipherMode mode);

        /**
         * @brief Get number of rounds for a given key size
         * @param ks KeySize enumeration value
         * @return 10, 12, or 14 rounds
         */
        unsigned int getNumRounds(KeySize ks);

        /**
         * @brief Get expanded key size in bytes
         * @param ks KeySize enumeration value
         * @return 176, 208, or 240 bytes
         */
        size_t getExpandedKeySizeBytes(KeySize ks);

        // =========================================================================
        // Base Classes
        // =========================================================================

        /**
         * @brief Abstract base class for all AES test vectors
         *
         * Provides common interface for accessing key information and test data.
         * All test vector classes should derive from this.
         */
        class TestVectorBase {
        protected:
            KeySize keySize_;
            Direction direction_;
            DataSource dataSource_;
            const unsigned char* key_;

            /// Protected constructor - only derived classes can instantiate
            TestVectorBase()
            : keySize_(KeySize::Unknown)
            , direction_(Direction::Encrypt)
            , dataSource_(DataSource::NIST_Official)
            , key_(nullptr)
            {}

        public:
            virtual ~TestVectorBase() = default;

            // Query methods
            KeySize getKeySize() const { return keySize_; }
            Direction getDirection() const { return direction_; }
            DataSource getDataSource() const { return dataSource_; }
            size_t getKeySizeBytes() const { return TestVectors::AES::getKeySizeBytes(keySize_); }

            // Data access
            std::vector<unsigned char> getKey() const;

            // Pure virtual interface - must be implemented by derived classes
            virtual const std::vector<unsigned char> getInput() const = 0;
            virtual const std::vector<unsigned char> getExpectedOutput() const = 0;
            virtual size_t getDataSize() const = 0;
        };

    } // namespace AES
} // namespace TestVectors

#endif // TEST_VECTORS_COMMON_HPP
