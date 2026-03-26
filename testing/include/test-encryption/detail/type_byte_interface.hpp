/**
 * @file type_byte_interface.hpp
 * @brief Byte conversion interfaces for cryptographic type testing
 *
 * Provides hierarchical interfaces for converting between typed cryptographic
 * structures (KeyExpansion, Block, IV) and raw byte arrays used in test vectors.
 *
 * @section organization Organization Pattern
 *
 * This file mirrors the structure of memory_callbacks.hpp:
 * - Base class in CryptoTest namespace (common operations)
 * - Specializations in sub-namespaces (BlockCipher, CipherMode, etc.)
 * - Each adds domain-specific operations (e.g., IV for cipher modes)
 *
 * @section usage Usage Pattern
 *
 * These interfaces work alongside MemoryCallbacks to form the complete
 * infrastructure required by Tester classes:
 *
 * @code
 * // Define byte operations
 * BlockCipher::TypeByteInterface<MyKE, MyBlock> byteOps{
 *     compareKE, buildKE, compareBlock, buildBlock
 * };
 *
 * // Define memory operations
 * BlockCipher::MemoryCallbacks<MyKE, MyBlock> memCallbacks{
 *     allocKE, freeKE, allocBlock, freeBlock
 * };
 *
 * // Create tester with both
 * BlockCipher::Tester<MyKE, MyBlock> tester(byteOps, memCallbacks);
 *
 * // Optionally validate infrastructure before running crypto tests
 * if (!tester.validateInfrastructure()) {
 *     std::cerr << "Infrastructure validation failed\n";
 *     return 1;
 * }
 * @endcode
 *
 * @section philosophy Design Philosophy
 *
 * **Separation of Concerns:**
 * - TypeByteInterface: Data conversion/comparison operations
 * - MemoryCallbacks: Allocation/deallocation operations
 * - Tester: Cryptographic correctness validation
 *
 * This separation allows:
 * - Independent testing of each component
 * - Flexible composition (mix different implementations)
 * - Clear responsibility boundaries
 *
 * **Trust with Optional Verification:**
 * - Framework ASSUMES these functions work correctly
 * - Provides validateByteOperations() as development aid
 * - Users should test their implementations independently
 * - Validation failures suggest infrastructure bugs, not crypto bugs
 *
 * @see memory_callbacks.hpp for complementary memory management
 * @see block_cipher_tester.hpp for usage in Tester class
 */

#include <gtest/gtest.h>
#include <iostream>
#include <functional>

namespace CryptoTest {

    /**
     * @brief Base interface for converting between typed structures and byte arrays
     *
     * Provides comparison and construction operations for cryptographic types
     * that need to interact with raw byte test vectors.
     *
     * @section design_rationale Design Rationale
     * - **Inheritance**: Avoids code duplication across BlockCipher/CipherMode
     * - **Protected destructor**: Prevents polymorphic deletion issues
     * - **Virtual validation**: Allows derived classes to extend checks
     *
     * @section user_responsibilities User Responsibilities
     *
     * The framework assumes that user-provided functions follow these contracts:
     *
     * **Comparison functions** (compareXXXBytes):
     * - Return true if typed structure matches byte array
     * - Return false otherwise
     * - Handle null pointers gracefully (return false)
     *
     * **Builder functions** (buildXXXFromBytes):
     * - Return 0 on success
     * - Return non-zero error code on failure
     * - Validate all inputs (null pointers, sizes)
     * - Do not modify input byte arrays
     *
     * Users should test these functions independently before integration.
     * The validateByteOperations() method provides basic sanity checking
     * but is NOT a substitute for thorough unit testing.
     *
     * @see BlockCipher::TypeByteInterface for usage in block cipher testing
     * @see CipherMode::TypeByteInterface for extension with IV operations
     * @see MemoryCallbacks for complementary memory management interface
     *
     * @tparam KE KeyExpansion type
     * @tparam BT Block type
     */
    template<typename KE, typename BT>
    struct TypeByteInterface {
    protected:
        // Core operations needed by all testers
        std::function<bool(const KE* const, size_t keySize, const unsigned char* const)>
            compareKeyExpansionBytes_;
        std::function<int(KE* const, size_t keySize, const unsigned char* const)>
            buildKeyExpansionFromBytes_;
        std::function<bool(const BT* const, const unsigned char* const)>
            compareBlockBytes_;
        std::function<int(BT* const, const unsigned char* const)>
            buildBlockFromBytes_;

        // Protected destructor prevents polymorphic deletion
        ~TypeByteInterface() = default;

    public:
        TypeByteInterface(
            std::function<bool(const KE* const, size_t keySize, const unsigned char* const)> compareKeyExpansionBytes,
            std::function<int(KE* const, size_t keySize, const unsigned char* const)>        buildKeyExpansionFromBytes,
            std::function<bool(const BT* const, const unsigned char* const)>                 compareBlockBytes,
            std::function<int(BT* const, const unsigned char* const)>                        buildBlockFromBytes
        ):
            compareKeyExpansionBytes_(compareKeyExpansionBytes),
            buildKeyExpansionFromBytes_(buildKeyExpansionFromBytes),
            compareBlockBytes_(compareBlockBytes),
            buildBlockFromBytes_(buildBlockFromBytes)
        {}

    protected:
        /**
         * @brief Validates that all function pointers are initialized
         * @return true if all base functions are non-null
         */
        bool validateBaseFunctions() const {
            return this->compareKeyExpansionBytes_ && this->buildKeyExpansionFromBytes_ && this->compareBlockBytes_ &&
                this->buildBlockFromBytes_;
        }

        /**
         * @brief Core validation logic for base byte operations
         *
         * @section validation_scope What This Tests
         *
         * This method performs basic sanity checks:
         * - Builder functions return 0 for valid input
         * - Comparison functions work after building
         * - Round-trip conversion preserves data (build → compare)
         * - Error codes returned for null pointers
         * - Error codes returned for invalid parameters
         *
         * @section validation_limits What This Does NOT Test
         *
         * - Actual cryptographic correctness (not this interface's job)
         * - Memory leaks (use Valgrind/ASan for this)
         * - Thread safety (single-threaded assumption)
         * - Performance characteristics
         * - Byte ordering correctness (endianness issues)
         *
         * @section philosophy Testing Philosophy
         *
         * We follow "trust, but verify when cheap":
         * - ASSUME user implementations work (their responsibility)
         * - PROVIDE basic checks as development aid
         * - DON'T require passing (users may skip validation)
         *
         * Think of this as "executable documentation" that demonstrates
         * expected behavior rather than comprehensive testing.
         *
         * @param keBuffer Pre-allocated KeyExpansion buffer
         * @param blockBuffer Pre-allocated Block buffer
         * @param keySize Key size in bits for testing (default: 128)
         * @return true if all basic checks pass, false otherwise
         *
         * @note Requires valid pre-allocated buffers (not null)
         * @note Cannot be called on base class (pure virtual validateFunctions)
         *
         * @warning Validation failures indicate bugs in YOUR comparison/builder
         *          functions, not in the cryptographic implementations being tested
         *
         * @see validateFunctions() to check if all pointers initialized
         */
        void validateBaseByteOperations(KE* keBuffer, BT* blockBuffer, size_t keySize = 128) const {
            if (!validateFunctions()) {
                FAIL() << "Function pointers not initialized";
                return;
            }

            if (!keBuffer || !blockBuffer) {
                FAIL() << "Null buffers provided";
                return;
            }

            SCOPED_TRACE("Base Byte Operations Validation");

            // Test KeyExpansion operations
            const unsigned char zeroKeyExpansion[240] = {0};

            int buildResult = this->buildKeyExpansionFromBytes_(keBuffer, keySize, zeroKeyExpansion);
            EXPECT_EQ(0, buildResult) << "Build KeyExpansion from bytes should succeed";

            if (buildResult == 0) {
                EXPECT_TRUE(this->compareKeyExpansionBytes_(keBuffer, keySize, zeroKeyExpansion))
                    << "Built KeyExpansion should match source bytes";
            }

            // Test error handling
            buildResult = this->buildKeyExpansionFromBytes_(nullptr, keySize, zeroKeyExpansion);
            EXPECT_NE(0, buildResult) << "Build should reject null output pointer";

            buildResult = this->buildKeyExpansionFromBytes_(keBuffer, 17, zeroKeyExpansion);  // Invalid size
            EXPECT_NE(0, buildResult) << "Build should reject invalid key size";

            // Test Block operations
            const unsigned char testBlock[16] = {
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
            };

            buildResult = this->buildBlockFromBytes_(blockBuffer, testBlock);
            EXPECT_EQ(0, buildResult) << "Build Block from bytes should succeed";

            if (buildResult == 0) {
                EXPECT_TRUE(this->compareBlockBytes_(blockBuffer, testBlock))
                    << "Round-trip: built Block should match source bytes";
            }

            // Test error handling
            buildResult = this->buildBlockFromBytes_(nullptr, testBlock);
            EXPECT_NE(0, buildResult) << "Build should reject null output pointer";
        }

    public:
        // Pure virtual for derived classes to implement full validation
        virtual bool validateFunctions() const = 0;

        // Pure virtual for derived classes to implement full operation validation
        virtual void validateByteOperations(KE* keBuffer, BT* blockBuffer, size_t keySize = 128) const = 0;
    };

    namespace BlockCipher {
        /**
         * @brief Byte interface specialization for block cipher testing
         *
         * Provides no additional operations beyond the base class, as block
         * cipher testing only requires KeyExpansion and Block conversions.
         *
         * @see CipherMode::TypeByteInterface for extension example (adds IV)
         * @see MemoryCallbacks for complementary memory management
         * @see Tester for usage in cryptographic testing
         *
         * @tparam KE KeyExpansion type
         * @tparam BT Block type
         */
        template<typename KE, typename BT>
        struct TypeByteInterface : protected CryptoTest::TypeByteInterface<KE, BT> {
            TypeByteInterface(
                std::function<bool(const KE* const, size_t keySize, const unsigned char* const)> compareKeyExpansionBytes,
                std::function<int(KE* const, size_t keySize, const unsigned char* const)>        buildKeyExpansionFromBytes,
                std::function<bool(const BT* const, const unsigned char* const)>                 compareBlockBytes,
                std::function<int(BT* const, const unsigned char* const)>                        buildBlockFromBytes
            ):
                CryptoTest::TypeByteInterface<KE, BT>(
                    compareKeyExpansionBytes, buildKeyExpansionFromBytes, compareBlockBytes, buildBlockFromBytes
                )
            {}

            bool compareKeyExpansionBytes(const KE* ke, size_t keySize, const unsigned char* bytes) const {
                return this->compareKeyExpansionBytes_(ke, keySize, bytes);
            }
            int buildKeyExpansionFromBytes(KE* ke, size_t keySize, const unsigned char* bytes) const {
                return this->buildKeyExpansionFromBytes_(ke, keySize, bytes);
            }
            bool compareBlockBytes(const BT* block, const unsigned char* bytes) const {
                return this->compareBlockBytes_(block, bytes);
            }
            int buildBlockFromBytes(BT* block, const unsigned char* bytes) const {
                return this->buildBlockFromBytes_(block, bytes);
            }

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
             * @note This method does NOT allocate or free buffers
             * @note Buffers must remain valid for the duration of this call
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
            void validateByteOperations(KE* keBuffer, BT* blockBuffer, size_t keySize = 128) const override {
                this->validateBaseByteOperations(keBuffer, blockBuffer, keySize);
            }

            virtual ~TypeByteInterface() = default;
        };
    }

    namespace CipherMode {
        /**
         * @brief Byte interface specialization for cipher mode testing
         *
         * Extends base with IV (Initial Vector) operations needed for
         * mode-of-operation testing (CBC, CTR, OFB, etc.).
         *
         * Demonstrates the extension pattern: derive from base, add
         * domain-specific operations, extend validation accordingly.
         *
         * @see BlockCipher::TypeByteInterface for simpler base-only version
         * @see MemoryCallbacks for complementary memory management
         *
         * @tparam KE KeyExpansion type
         * @tparam BT Block type
         * @tparam IV Initial Vector type
         */
        template<typename KE, typename BT, typename IV>
        struct TypeByteInterface : public CryptoTest::TypeByteInterface<KE, BT> {
            std::function<bool(const IV* const, const unsigned char* const)> compareIVBytes_;
            std::function<int(IV* const, const unsigned char* const)>        buildIVFromBytes_;

            TypeByteInterface(
                std::function<bool(const KE* const, size_t keySize, const unsigned char* const)> compareKeyExpansionBytes,
                std::function<int(KE* const, size_t keySize, const unsigned char* const)>        buildKeyExpansionFromBytes,
                std::function<bool(const BT* const, const unsigned char* const)>                 compareBlockBytes,
                std::function<int(BT* const, const unsigned char* const)>                        buildBlockFromBytes,
                std::function<bool(const IV* const, const unsigned char* const)>                 compareIVBytes,
                std::function<int(IV* const, const unsigned char* const)>                        buildIVFromBytes
            ):
                CryptoTest::TypeByteInterface<KE, BT>(
                    compareKeyExpansionBytes, buildKeyExpansionFromBytes, compareBlockBytes, buildBlockFromBytes
                ),
                compareIVBytes_(compareIVBytes),
                buildIVFromBytes_(buildIVFromBytes)
            {}

            bool validateFunctions() const override {
                return this->validateBaseFunctions() && this->compareIVBytes_ && this->buildIVFromBytes_;
            }

            /**
             * @brief Validate all byte operations including IV
             *
             * Extends base validation with IV-specific checks. Requires an
             * additional IV buffer parameter.
             *
             * @param keBuffer Pre-allocated KeyExpansion buffer
             * @param blockBuffer Pre-allocated Block buffer
             * @param ivBuffer Pre-allocated IV buffer
             * @param keySize Key size for testing (default: 128 bits)
             * @return true if all validation passes
             *
             * @note All buffers must be pre-allocated and valid
             * @note This method does NOT allocate or free buffers
             */
            void validateByteOperations(KE* keBuffer, BT* blockBuffer, IV* ivBuffer, size_t keySize = 128) const override {
                // First validate base operations (KE and Block)
                this->validateBaseByteOperations(keBuffer, blockBuffer, keySize);

                SCOPED_TRACE("IV Byte Operation Validation");

                const unsigned char testIV[16] = {
                    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
                    0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf
                };

                int buildResult = this->buildIVFromBytes_(ivBuffer, testIV);
                EXPECT_EQ(0, buildResult) << "Build IV from bytes should succeed";

                if (buildResult == 0) {
                    EXPECT_TRUE(this->compareIVBytes_(ivBuffer, testIV))
                        << "Built IV should match source bytes";
                }

                buildResult = this->buildIVFromBytes_(nullptr, testIV);
                EXPECT_NE(0, buildResult) << "Build should reject null output pointer";
            }
        };
    }
}
