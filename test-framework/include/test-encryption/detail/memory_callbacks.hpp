#ifndef CRYPTO_TEST_DETAIL_MEMORY_CALLBACKS_HPP
#define CRYPTO_TEST_DETAIL_MEMORY_CALLBACKS_HPP

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
     * If your KeyExpansionType allocates memory dynamically, it MUST know
     * the key size at allocation time. Block allocation doesn't need size
     * since AES blocks are always 16 bytes.
     *
     * @note All function pointers should handle edge cases gracefully
     * @note Free functions should handle null pointers (no-op)
     */
    template<typename KE, typename BT>
    struct MemoryCallbacksBase {
    protected:
        std::function<KE*(size_t keySizeBits)>  allocateKeyExpansion;
        std::function<void(KE**)>               freeKeyExpansion;
        std::function<BT*()>                    allocateBlock;
        std::function<void(BT**)>               freeBlock;
    protected:
        // Preventing polymorphic deletion.
        ~MemoryCallbacksBase();

    public:
        virtual bool noNullFunctionPointer() const = 0;
    };

    namespace BlockCipher {

        /**
         * @brief Memory management callbacks for block C-style cipher structures
         */
        template<typename KE, typename BT>
        struct MemoryCallbacks: protected MemoryCallbacksBase<KE, BT>{

            bool noNullFunctionPointer() const override {
                return this->allocateKeyExpansion && this->freeKeyExpansion && this->allocateBlock && this->freeBlock;
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
                return this->allocateKeyExpansion && this->freeKeyExpansion && this->allocateBlock && this->freeBlock &&
                    this->allocateIV && this->freeIV;
            }
        };

    } // namespace CipherMode

} // namespace CryptoTest

#endif // CRYPTO_TEST_DETAIL_MEMORY_CALLBACKS_HPP
