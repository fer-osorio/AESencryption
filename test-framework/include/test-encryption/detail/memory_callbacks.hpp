#ifndef CRYPTO_TEST_DETAIL_MEMORY_CALLBACKS_HPP
#define CRYPTO_TEST_DETAIL_MEMORY_CALLBACKS_HPP

#include "../../test_framework.hpp"
#include <functional>
#include <cstddef>

namespace CryptoTest {

    // ========== Block Cipher Memory Callbacks ==========

    /**
     * @brief Memory management callbacks for C-style cipher structures
     *
     * Since C structures lack constructors/destructors, users must provide
     * functions to allocate and deallocate resources. This structure bundles
     * all required memory management callbacks.
     *
     * @tparam KE KeyExpansion type
     * @tparam BT Block type
     *
     * @section key_size_allocation Why KeyExpansion Needs Key Size
     *
     * AES key expansion produces different amounts of data:
     * - AES-128: 11 round keys (176 bytes)
     * - AES-192: 13 round keys (208 bytes)
     * - AES-256: 15 round keys (240 bytes)
     *
     * If your KE allocates memory dynamically, it MUST know
     * the key size at allocation time. Block allocation doesn't need size
     * since AES blocks are always 16 bytes.
     *
     * @note All function pointers should handle edge cases gracefully
     * @note Free functions should handle null pointers (no-op)
     */
    template<typename KE, typename BT>
    struct MemoryCallbacksBase {
    protected:
        std::function<KE*(size_t keySize)>  allocateKeyExpansion;
        std::function<void(KE**)>           freeKeyExpansion;
        std::function<BT*()>                allocateBlock;
        std::function<void(BT**)>           freeBlock;
    protected:
        // Preventing polymorphic deletion.
        ~MemoryCallbacksBase();

        /**
         * @brief Validates if all base pointers to functions are not null.
         * @return True if all function pointers are not null, false otherwise.
         */
        bool noNullFunctionPointerBase() const {
            return this->allocateKeyExpansion && this->freeKeyExpansion && this->allocateBlock && this->freeBlock;
        }

        /**
         * @brief Validates memory management for base callbacks (optional sanity check)
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
        bool validateMemoryCallbacksBase() {
            TEST_SUITE("Basic Memory Callback Validation");

            if (!this->noNullFunctionPointer()) {
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
         * @brief Destinated to flag null function pointers.
         */
        virtual bool noNullFunctionPointer() const = 0;

        /**
         * @brief Destinated to implement basic memory management tests.
         */
        virtual bool validateMemoryCallbacks() const = 0;
    };

    namespace BlockCipher {

        /**
         * @brief Memory management callbacks for block C-style cipher structures
         */
        template<typename KE, typename BT>
        struct MemoryCallbacks: protected MemoryCallbacksBase<KE, BT>{

            /**
             * @brief Validates if all pointers to functions are not null.
             * @return True if all function pointers are not null, false otherwise.
             */
            bool noNullFunctionPointer() const override {
                return this->noNullFunctionPointerBase();
            }

            /**
             * @brief Validates memory management for callbacks (optional sanity check)
             * @return True if all basic checks pass, false otherwise
             */
            bool validateMemoryCallbacks() const override{
                return this->validateMemoryCallbacksBase();
            }
        };

    } // namespace BlockCipher

    // ========== Cipher Mode Memory Callbacks ==========

    namespace CipherMode {

        /**
         * @brief Memory management callbacks for cipher C-style mode structures
         */
        template<typename KE, typename BT, typename IV>
        struct MemoryCallbacks: protected MemoryCallbacksBase<KE, BT>{
            std::function<IV*()> allocateIV;
            std::function<void(IV**)> freeIV;

            bool noNullFunctionPointer() const override {
                return this->noNullFunctionPointerBase() && this->allocateIV && this->freeIV;
            }

            bool validateMemoryCallbacks() const override{
                bool partial_check = this->validateMemoryCallbacksBase();

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

                return SUITE_PASSED();
            }
        };

    } // namespace CipherMode

} // namespace CryptoTest

#endif // CRYPTO_TEST_DETAIL_MEMORY_CALLBACKS_HPP
