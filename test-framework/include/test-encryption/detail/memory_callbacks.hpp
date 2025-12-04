/**
 * @file memory_callbacks.hpp
 * @brief Memory management callback structures for cryptographic testing
 *
 * Provides RAII-compatible memory management interfaces for C-style
 * cryptographic structures that lack constructors/destructors.
 * Organized by testing namespace (BlockCipher, CipherMode, etc.)
 *
 * @section design Design Pattern
 * Uses inheritance to share common allocation logic (KeyExpansion, Block)
 * while allowing specializations to add domain-specific allocations (IV, MAC).
 */

#ifndef CRYPTO_TEST_DETAIL_MEMORY_CALLBACKS_HPP
#define CRYPTO_TEST_DETAIL_MEMORY_CALLBACKS_HPP

#include "../../test_framework.hpp"
#include <functional>
#include <cstddef>

namespace CryptoTest {

    // ========== Base Memory Callbacks ==========

    /**
     * @brief Base class for memory management callbacks
     *
     * Provides common allocation/deallocation for KeyExpansion and Block types.
     * Derived classes extend this with additional type-specific allocations
     * (e.g., IV for cipher modes, MAC for authenticated modes).
     *
     * @section design_rationale Design Rationale
     * - **Inheritance**: Avoids code duplication across BlockCipher/CipherMode
     * - **Protected destructor**: Prevents polymorphic deletion issues
     * - **Virtual validation**: Allows derived classes to extend checks
     *
     * @tparam KE KeyExpansion type
     * @tparam BT Block type
     */
    template<typename KE, typename BT>
    struct MemoryCallbacks {
    protected:
        std::function<KE*(size_t keySize)>  allocateKeyExpansion;
        std::function<void(KE**)>           freeKeyExpansion;
        std::function<BT*()>                allocateBlock;
        std::function<void(BT**)>           freeBlock;
    protected:
        /**
         * @brief Protected destructor prevents polymorphic deletion
         *
         * This is intentional: MemoryCallbacks should be used as value types,
         * not via base class pointers. Matches the pattern used in TypeByteInterface.
         */
        ~MemoryCallbacks() = default;

        /**
         * @brief Validates if all base function pointers are initialized
         * @return true if all function pointers are non-null, false otherwise
         *
         * @note Derived classes should call this AND check their own functions
         */
        bool validateBaseFunctions() const {
            return this->allocateKeyExpansion && this->freeKeyExpansion && this->allocateBlock && this->freeBlock;
        }

        /**
         * @brief Validates memory management for base callbacks (optional sanity check)
         *
         * @section philosophy Validation Philosophy
         * This framework follows "trust, but verify when cheap":
         * - We ASSUME user allocators work (their infrastructure, their responsibility)
         * - We PROVIDE basic validation as a development aid
         * - We DON'T require passing (users may have valid reasons to skip)
         *
         * This method performs basic validation of the memory management functions
         * to catch common errors before running the full test suite. It tests:
         * - Allocation functions return non-null pointers
         * - Deallocation functions handle null pointers gracefully
         * - Deallocation properly nullifies the pointer
         * - KeyExpansion allocation works for all three AES key sizes
         * - Multiple simultaneous allocations work correctly
         *
         * @return true if all basic checks pass, false otherwise
         *
         * @note This method works with opaque/incomplete types (forward declarations)
         * @note Cannot test memory contents with sizeof() on incomplete types
         *
         * @warning This does NOT guarantee correctness; it only catches obvious errors
         * @warning Memory leaks cannot be detected by this method
         * @warning Cannot validate actual memory size (hidden by opaque type design)
         * @note Users should still test their memory management functions independently
         * @note This is a convenience function; failures here suggest user function bugs
         *
         * @example
         * @code
         * if (!tester.validateMemoryCallbacks()) {
         *     std::cerr << "Memory callbacks appear broken; fix before running tests" << std::endl;
         *     return 1;
         * }
         * @endcode
         */
        bool validateBaseMemoryCallbacks() {
            TEST_SUITE("Basic Memory Callback Validation");

            if (!this->validateBaseFunctions()) {
                std::cerr << "ERROR: Memory callbacks struct is not fully initialized" << std::endl;
                return false;
            }

            // Test KeyExpansion allocation for all three key sizes
            const size_t keySizes[] = {128, 192, 256};
            for (size_t keySize : keySizes) {
                KE* testKE = this->allocateKeyExpansion(keySize);

                std::string msg = "KeyExpansion allocation for " + std::to_string(keySize) +
                "-bit key should return non-null";
                ASSERT_NOT_NULL(
                    testKE, msg.c_str()
                );

                if (testKE) {
                    // Note: We cannot use sizeof() on opaque/incomplete types
                    // The allocation function is responsible for allocating the correct size
                    // We can only test that allocation succeeded and deallocation works

                    // Test deallocation
                    this->freeKeyExpansion(&testKE);
                    ASSERT_TRUE(
                        testKE == nullptr,
                        "KeyExpansion free should nullify pointer"
                    );
                }
            }

            // Test that free handles already-null pointer gracefully
            KE* testKE = nullptr;
            this->freeKeyExpansion(&testKE);
            ASSERT_TRUE(
                testKE == nullptr,
                "KeyExpansion free should handle null pointer gracefully"
            );

            // Test Block allocation
            BT* testBlock = this->allocateBlock();
            ASSERT_NOT_NULL(
                testBlock,
                "Block allocation should return non-null"
            );

            if (testBlock) {
                // Note: Cannot use sizeof() on incomplete types
                // Block allocation function is responsible for correct sizing

                this->freeBlock(&testBlock);
                ASSERT_TRUE(testBlock == nullptr,
                "Block free should nullify pointer");
            }

            testBlock = nullptr;
            this->freeBlock(&testBlock);
            ASSERT_TRUE(
                testBlock == nullptr,
                "Block free should handle null pointer gracefully"
            );

            // Test multiple simultaneous allocations
            KE* ke128 = this->allocateKeyExpansion(128);
            KE* ke256 = this->allocateKeyExpansion(256);
            BT* b1 = this->allocateBlock();
            BT* b2 = this->allocateBlock();

            ASSERT_NOT_NULL(ke128, "AES-128 KeyExpansion allocation");
            ASSERT_NOT_NULL(ke256, "AES-256 KeyExpansion allocation");
            ASSERT_NOT_NULL(b1, "First Block allocation");
            ASSERT_NOT_NULL(b2, "Second Block allocation");

            ASSERT_TRUE(
                ke128 != ke256,
                "Different KeyExpansion allocations should return different pointers"
            );
            ASSERT_TRUE(
                b1 != b2,
                "Multiple Block allocations should return different pointers"
            );

            // Clean up
            if (ke128) this->freeKeyExpansion(&ke128);
            if (ke256) this->freeKeyExpansion(&ke256);
            if (b1) this->freeBlock(&b1);
            if (b2) this->freeBlock(&b2);

            PRINT_RESULTS();

            if (!SUITE_PASSED()) {
                std::cout << "\n"
                << "=================================================================\n"
                << "WARNING: Memory callback validation failed!\n"
                << "This suggests bugs in your allocation/deallocation functions.\n"
                << "Please fix these issues before running cryptographic tests.\n"
                << "=================================================================\n"
                << std::endl;
            }

            return SUITE_PASSED();
        }

    public:
        /**
         * @brief Check if all required function pointers are initialized
         * @return true if no null function pointers exist
         *
         * Pure virtual - derived classes must implement to check all their functions.
         */
        virtual bool validateFunctions() const = 0;

        /**
         * @brief Validate memory management operations (optional sanity check)
         * @return true if basic allocation/deallocation tests pass
         *
         * Pure virtual - derived classes should call validateBaseMemoryCallbacks()
         * and add any additional validation for their specialized types.
         *
         * @see validateBaseMemoryCallbacks() for base implementation
         */
        virtual bool validateMemoryCallbacks() const = 0;
    };

    // ========== Block Cipher Memory Callbacks ==========

    /**
     * @namespace CryptoTest::BlockCipher
     * @brief Block cipher testing utilities
     *
     * Contains MemoryCallbacks (this file) and TypeByteInterface (type_byte_interface.hpp)
     * which are used together by the Tester class (block_cipher_tester.hpp).
     */
    namespace BlockCipher {
        /**
         * @brief Memory management callbacks for block cipher testing
         *
         * Specialization of base callbacks that adds no additional allocations
         * (block ciphers only need KeyExpansion and Block).
         *
         * @see CipherMode::MemoryCallbacks for extension example (adds IV)
         * @see TypeByteInterface for the complementary byte operation interface
         */
        template<typename KE, typename BT>
        struct MemoryCallbacks: protected CryptoTest::MemoryCallbacks<KE, BT>{

            /**
             * @brief Check if all required function pointers are initialized
             * @return true if no null function pointers exist
             */
            bool validateFunctions() const override {
                return this->validateBaseFunctions();
            }

            /**
             * @brief Validate memory management operations (optional sanity check)
             * @return true if basic allocation/deallocation tests pass
             *
             * * @see validateBaseMemoryCallbacks() for base implementation
             */
            bool validateMemoryCallbacks() const override{
                return this->validateBaseMemoryCallbacks();
            }
        };

    } // namespace BlockCipher

    // ========== Cipher Mode Memory Callbacks ==========

    /**
     * @namespace CryptoTest::CipherMode
     * @brief Cipher mode testing utilities
     *
     * Contains MemoryCallbacks (this file) and TypeByteInterface (type_byte_interface.hpp)
     * which are used together by the Tester class (cipher_mode_tester.hpp).
     */
    namespace CipherMode {

        /**
         * @brief Memory management callbacks for cipher mode testing
         *
         * Extends base callbacks with IV (Initial Vector) allocation/deallocation.
         * Demonstrates the extension pattern for adding type-specific allocations.
         *
         * @tparam IV Initial Vector type (typically 16 bytes for AES modes)
         *
         * @see BlockCipher::MemoryCallbacks for simpler base-only version
         * @see validateMemoryCallbacks() for validation of IV operations
         */
        template<typename KE, typename BT, typename IV>
        struct MemoryCallbacks: protected CryptoTest::MemoryCallbacks<KE, BT>{
            std::function<IV*()> allocateIV;
            std::function<void(IV**)> freeIV;

            /**
             * @brief Check if all required function pointers are initialized
             * @return true if no null function pointers exist
             */
            bool validateFunctions() const override {
                return this->validateBaseFunctions() && this->allocateIV && this->freeIV;
            }

            /**
             * @brief Validate memory management operations (optional sanity check)
             * @return true if basic allocation/deallocation tests pass
             *
             * * @see validateBaseMemoryCallbacks() for base implementation
             */
            bool validateMemoryCallbacks() const override {
                bool baseValid = this->validateBaseMemoryCallbacks();

                TEST_SUITE("Initial Vector Memory Callback Validation");

                // Test Initial Vector allocation
                IV* testIV = this->allocateIV();
                ASSERT_NOT_NULL(
                    testIV,
                    "Initial Vector allocation should return non-null"
                );
                if (testIV) {
                    // Note: Cannot use sizeof() on incomplete types
                    // Initial Vector allocation function is responsible for correct sizing
                    this->freeBlock(&testIV);
                    ASSERT_TRUE(testIV == nullptr,
                    "Initial Vector free should nullify pointer");
                }

                testIV = nullptr;
                this->freeBlock(&testIV);
                ASSERT_TRUE(
                    testIV == nullptr,
                    "Initial Vector free should handle null pointer gracefully"
                );

                // Test multiple simultaneous allocations
                IV* iv1 = this->allocateIV();
                IV* iv2 = this->allocateIV();
                ASSERT_NOT_NULL(iv1, "First Initial Vector allocation");
                ASSERT_NOT_NULL(iv2, "Second Initial Vector allocation");

                ASSERT_TRUE(
                    iv1 != iv2,
                    "Multiple Initial Vector allocations should return different pointers"
                );

                // Clean up
                if (iv1) this->freeIV(&iv1);
                if (iv2) this->freeIV(&iv2);

                PRINT_RESULTS();

                if (!SUITE_PASSED()) {
                    std::cout << "\n"
                    << "=================================================================\n"
                    << "WARNING: Memory callback validation for initial vector failed!\n"
                    << "This suggests bugs in your allocation/deallocation functions.\n"
                    << "Please fix these issues before running cryptographic tests.\n"
                    << "=================================================================\n"
                    << std::endl;
                }

                return SUITE_PASSED() && baseValid;
            }
        };

    } // namespace CipherMode

} // namespace CryptoTest

#endif // CRYPTO_TEST_DETAIL_MEMORY_CALLBACKS_HPP
