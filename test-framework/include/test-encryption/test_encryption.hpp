/**
 * @file test_encryption.hpp
 * @brief Main include for cryptographic testing framework (header-only library)
 *
 * This is a header-only template library for testing C-style cryptographic
 * implementations. Simply include this file to access all testing utilities.
 *
 * @section organization File Organization
 *
 * This library uses a header-only design (like STL, Boost, Eigen):
 *
 * ```
 * test-framework/
 * ├── test_encryption.hpp       # ← Main include (this file)
 * │   └── Includes all detail headers below
 * │
 * └── detail/                          # Implementation details
 *     ├── memory_callbacks.hpp         # MemoryCallbacks for all namespaces
 *     ├── common_utilities.hpp         # Shared utilities
 *     ├── block_cipher_tester.hpp      # BlockCipher::Tester implementation
 *     └── cipher_mode_tester.hpp       # CipherMode::Tester implementation
 * ```
 *
 * Users should ONLY include test_encryption.hpp, never the detail/ headers.
 *
 * @section rationale Why Header-Only?
 *
 * Template code must be available at compile time. Header-only design:
 * - Simplifies usage (one #include)
 * - Enables full optimization (everything can be inlined)
 * - Avoids linking issues
 * - Standard for template libraries
 *
 * Trade-off: Longer compile times, but acceptable for test code.
 *
 * @section usage Usage Example
 *
 * @code
 * // Just include the main header
 * #include "test_encryption.hpp"
 *
 * using namespace CryptoTest;
 *
 * // Block cipher testing
 * BlockCipher::MemoryCallbacks<MyKE, MyBlock> callbacks{...};
 * BlockCipher::Tester<MyKE, MyBlock> tester(..., callbacks);
 * tester.runTestSuite(...);
 *
 * // Cipher mode testing
 * CipherMode::MemoryCallbacks<MyKE, MyBlock, MyIV> modeCallbacks{...};
 * CipherMode::Tester<MyKE, MyBlock, MyIV> modeTester(..., modeCallbacks);
 * modeTester.runTestSuite(...);
 * @endcode
 *
 * @warning Do not include detail/ headers directly - always use this main header
 */

#ifndef TEST_ENCRYPTION_HPP
#define TEST_ENCRYPTION_HPP

// Include all implementation detail headers
// Order matters: dependencies first
#include "detail/common_utilities.hpp"
#include "detail/memory_callbacks.hpp"
#include "detail/block_cipher_tester.hpp"
#include "detail/cipher_mode_tester.hpp"
// Future additions:
// #include "detail/authenticated_mode_tester.hpp"

/**
 * @namespace CryptoTest
 * @brief Root namespace for cryptographic testing utilities
 *
 * All testing utilities are organized under this namespace:
 *
 * - **CryptoTest::Common** - Shared utilities (error codes, helpers)
 * - **CryptoTest::BlockCipher** - Single-block cipher testing
 * - **CryptoTest::CipherMode** - Mode of operation testing (CBC, CTR, OFB)
 * - **CryptoTest::AuthenticatedMode** - AEAD testing (future: GCM, CCM)
 *
 * Each sub-namespace contains:
 * - `MemoryCallbacks<...>` struct for memory management
 * - `Tester<...>` class for running tests
 * - Helper functions as needed
 *
 * @section design_philosophy Design Philosophy
 *
 * **Namespace-based organization:**
 * - Clear separation of concerns
 * - Consistent naming (always `Tester` class)
 * - Easy to extend without affecting existing code
 * - Mirrors industry standards (std::, boost::)
 *
 * **Header-only library:**
 * - Templates require definitions at compile time
 * - Simplifies build process
 * - Enables compiler optimizations
 * - Standard practice for template libraries
 *
 * **Opaque type support:**
 * - Works with forward-declared C structures
 * - Respects encapsulation
 * - No sizeof() dependencies on incomplete types
 */
namespace CryptoTest {
    // All implementations are in detail/ headers included above
    // This namespace exists for documentation and organization
}

#endif // TEST_ENCRYPTION_HPP
