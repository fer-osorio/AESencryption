#include "../../test_framework.hpp"
#include <iostream>
#include <functional>

namespace CryptoTest {

    /**
     * @brief Base interface for converting between typed structures and byte arrays
     *
     * Provides comparison and construction operations for cryptographic types
     * that need to interact with raw byte test vectors.
     *
     * @tparam KE KeyExpansion type
     * @tparam BT Block type
     */
    template<typename KE, typename BT>
    struct TypeByteInterface {
    protected:
        // Core operations needed by all testers
        std::function<bool(const KE* const, size_t keySize, const unsigned char* const)>
            compareKeyExpansionBytes;
        std::function<int(KE* const, size_t keySize, const unsigned char* const)>
            buildKeyExpansionFromBytes;
        std::function<bool(const BT* const, const unsigned char* const)>
            compareBlockBytes;
        std::function<int(BT* const, const unsigned char* const)>
            buildBlockFromBytes;

        // Protected destructor prevents polymorphic deletion
        ~TypeByteInterface() = default;

        /**
         * @brief Validates that all function pointers are initialized
         * @return true if all base functions are non-null
         */
        bool validateBaseFunctions() const {
            return compareKeyExpansionBytes && buildKeyExpansionFromBytes && compareBlockBytes &&
                buildBlockFromBytes;
        }

        /**
         * @brief Core validation logic
         * @param keBuffer Pre-allocated KeyExpansion buffer
         * @param blockBuffer Pre-allocated Block buffer
         * @param keySize Key size in bits for testing
         * @return true if validation passes
         */
        bool validateBaseByteOperations(KE* keBuffer, BT* blockBuffer, size_t keySize = 128) const {
            if (!validateFunctions()) {
                std::cerr << "ERROR: Function pointers not initialized\n";
                return false;
            }

            if (!keBuffer || !blockBuffer) {
                std::cerr << "ERROR: Null buffers provided\n";
                return false;
            }

            TEST_SUITE("Base Byte Operations Validation");

            // Test KeyExpansion operations
            const unsigned char zeroKeyExpansion[240] = {0};

            int buildResult = buildKeyExpansionFromBytes(keBuffer, keySize, zeroKeyExpansion);
            ASSERT_EQUAL(
                0, buildResult, "Build KeyExpansion from bytes should succeed"
            );

            if (buildResult == 0) {
                ASSERT_TRUE(
                    compareKeyExpansionBytes(keBuffer, keySize, zeroKeyExpansion),
                    "Built KeyExpansion should match source bytes"
                );
            }

            // Test error handling
            buildResult = buildKeyExpansionFromBytes(nullptr, keySize, zeroKeyExpansion);
            ASSERT_TRUE(
                buildResult != 0, "Build should reject null output pointer"
            );

            buildResult = buildKeyExpansionFromBytes(keBuffer, 17, zeroKeyExpansion);  // Invalid size
            ASSERT_TRUE(
                buildResult != 0, "Build should reject invalid key size"
            );

            // Test Block operations
            const unsigned char testBlock[16] = {
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
            };

            buildResult = buildBlockFromBytes(blockBuffer, testBlock);
            ASSERT_EQUAL(
                0, buildResult, "Build Block from bytes should succeed"
            );

            if (buildResult == 0) {
                ASSERT_TRUE(
                    compareBlockBytes(blockBuffer, testBlock),
                    "Round-trip: built Block should match source bytes"
                );
            }

            // Test error handling
            buildResult = buildBlockFromBytes(nullptr, testBlock);
            ASSERT_TRUE(
                buildResult != 0, "Build should reject null output pointer"
            );

            PRINT_RESULTS();

            if (!SUITE_PASSED()) {
                std::cout << "\n"
                << "⚠️  WARNING: Byte operation validation failed\n"
                << "This suggests issues in your comparison/builder functions.\n"
                << "Fix these before running cryptographic tests.\n";
            }

            return SUITE_PASSED();
        }

    public:
        // Pure virtual for derived classes to implement full validation
        virtual bool validateFunctions() const = 0;
        // Pure virtual for derived classes to implement full operation validation
        bool validateByteOperations(KE* keBuffer, BT* blockBuffer, size_t keySize) const = 0;
    };

    namespace BlockCipher {
        /**
         * @brief Byte interface specialization for block cipher testing
         */
        template<typename KE, typename BT>
        struct TypeByteInterface : protected CryptoTest::TypeByteInterface<KE, BT> {
            bool validateFunctions() const override {
                return this->validateBaseFunctions();
            }

            /**
             * @brief Validate byte operations with user-provided buffers
             *
             * This is the manual approach - you manage allocation/deallocation.
             * Use this when you want full control or already have buffers allocated.
             *
             * @param keBuffer Pre-allocated KeyExpansion buffer
             * @param blockBuffer Pre-allocated Block buffer
             * @param keySize Key size for testing (default: 128 bits)
             * @return true if validation passes
             *
             * @example
             * @code
             * MyKE* ke = allocateKE(128);
             * MyBlock* block = allocateBlock();
             *
             * bool valid = byteInterface.validateByteOperations(ke, block);
             *
             * freeKE(&ke);
             * freeBlock(&block);
             * @endcode
             */
            bool validateByteOperations(KE* keBuffer, BT* blockBuffer, size_t keySize = 128) const {
                return this->validateBaseByteOperations(keBuffer, blockBuffer, keySize);
            }

        };
    }

    namespace CipherMode {
        /**
         * @brief Byte interface specialization for cipher mode testing
         * Extends base with IV operations
         */
        template<typename KE, typename BT, typename IV>
        struct TypeByteInterface : public CryptoTest::TypeByteInterface<KE, BT> {
            std::function<bool(const IV* const, const unsigned char* const)> compareIVBytes;
            std::function<int(IV* const, const unsigned char* const)>        buildIVFromBytes;

            bool validateFunctions() const override {
                return this->validateBaseFunctions() && compareIVBytes && buildIVFromBytes;
            }

            // Override base validation to include IV testing
            bool validateByteOperations(KE* keBuffer, BT* blockBuffer, IV* ivBuffer, size_t keySize = 128) const override {
                // First validate base operations (KE and Block)
                bool baseValid = this->validateBaseByteOperations(keBuffer, blockBuffer, keySize);

                if (!baseValid) return false;

                TEST_SUITE("IV Byte Operation Validation");

                const unsigned char testIV[16] = {
                    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
                    0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf
                };

                int buildResult = buildIVFromBytes(ivBuffer, testIV);
                ASSERT_EQUAL(0, buildResult, "Build IV from bytes should succeed");

                if (buildResult == 0) {
                    ASSERT_TRUE(
                        compareIVBytes(ivBuffer, testIV),
                        "Built IV should match source bytes"
                    );
                }

                buildResult = buildIVFromBytes(nullptr, testIV);
                ASSERT_TRUE(
                    buildResult != 0, "Build should reject null output pointer"
                );

                PRINT_RESULTS();
                return SUITE_PASSED();
            }
        };
    }
}
