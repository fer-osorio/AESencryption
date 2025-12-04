/**
 * @file block_cipher_tester.hpp
 * @brief Template-based testing framework for C-style symmetric encryption functions
 *
 * @section dependencies Dependencies
 * This tester requires two infrastructure components:
 * - **MemoryCallbacks**: Allocation/deallocation for C structures
 * - **TypeByteInterface**: Conversion between types and raw bytes
 *
 * Both can be optionally validated before running cryptographic tests.
 *
 * This file provides a reusable testing framework for validating C-style cryptographic
 * implementations. It abstracts key expansion, encryption, and decryption operations
 * through std::function wrappers, allowing the same test logic to work with different
 * implementations (C structs, C++ classes, etc.).
 *
 * @tparam KeyExpansionType Type representing expanded key material (e.g., struct containing round keys)
 * @tparam BlockType Type representing a cipher block (e.g., 16-byte AES block)
 *
 * @example
 * @code
 * // Define comparison and builder functions for your implementation
 * auto compareKE = [](const MyKeyExpansion* ke, size_t keySize, const uint8_t* expected) { ... };
 * auto buildKE = [](MyKeyExpansion* ke, size_t keySize, const uint8_t* key) { ... };
 * auto compareBlock = [](const MyBlock* block, const uint8_t* expected) { ... };
 * auto buildBlock = [](const MyBlock* block, const uint8_t* data) { ... };
 *
 * // Create tester instance
 * Tester<MyKeyExpansion, MyBlock> tester(compareKE, buildKE, compareBlock, buildBlock);
 *
 * // Run tests with NIST test vectors
 * auto tv = TestVectors::AES::FIPS197::Cipher::create(KeySize::AES128);
 * MyKeyExpansion ke_buffer;
 * MyBlock input_buffer, output_buffer;
 * bool success = tester.testEncryptBlock(*tv, myEncryptFunc, &ke_buffer, &input_buffer, &output_buffer);
 * @endcode
 */

#ifndef BLOCK_CIPHER_TESTER_HPP
#define BLOCK_CIPHER_TESTER_HPP

#include "../../test-vectors/fips197_key_expansion.hpp"
#include "../../test-vectors/fips197_cipher.hpp"
#include "../../test_framework.hpp"
#include "memory_callbacks.hpp"
#include "type_byte_interface.hpp"
#include <cstddef>
#include <functional>

namespace ke = TestVectors::AES::FIPS197::KeyExpansion;
namespace cp = TestVectors::AES::FIPS197::Cipher;


/**
 * @brief Template-based testing framework for C-style symmetric encryption implementations
 *
 * This class provides a suite of test methods for validating key expansion, encryption,
 * and decryption functions. It uses std::function to abstract the actual implementation,
 * making it suitable for testing various C-style APIs without code duplication.
 *
 * The framework follows these design principles:
 * - Configurable memory management (user provides allocation/deallocation)
 * - Consistent error conventions (0 = success, non-zero = failure)
 * - Support for NIST FIPS 197 test vectors
 *
 * @section infrastructure Infrastructure Requirements
 *
 * The Tester class requires two types of callbacks:
 *
 * 1. **TypeByteInterface**: Comparison and construction functions
 *    - compareKeyExpansionBytes: Compare KE with byte array
 *    - buildKeyExpansionFromBytes: Construct KE from bytes
 *    - compareBlockBytes: Compare Block with byte array
 *    - buildBlockFromBytes: Construct Block from bytes
 *
 * 2. **MemoryCallbacks** (optional for runTestSuite):
 *    - allocateKeyExpansion: Allocate KE with key size
 *    - freeKeyExpansion: Deallocate and nullify KE
 *    - allocateBlock: Allocate Block (fixed size)
 *    - freeBlock: Deallocate and nullify Block
 *
 * These are separated to match the single-responsibility principle:
 * memory management vs. data operations are distinct concerns.
 *
 * @section usage Usage
 *
 * Users have two options for memory management:
 *
 * **Option 1: Automatic (Recommended)** - Provide memory callbacks and use runTestSuite():
 * @code
 * MemoryCallbacks<MyKE, MyBlock> callbacks{
 *     // KeyExpansion needs key size (128, 192, or 256 bits)
 *     [](size_t keySizeBits) { return MyKEAlloc(keySizeBits); },
 *     [](MyKE** p) { MyKEFree(p); },
 *     // Block is always 16 bytes, no size needed
 *     []() { return MyBlockAlloc(); },
 *     [](MyBlock** p) { MyBlockFree(p); }
 * };
 * Tester tester(compare, build, compare, build, callbacks);
 * tester.runTestSuite(KeySize::AES128, keyBuilder, encrypt, decrypt);
 * @endcode
 *
 * **Option 2: Manual** - Manage buffers yourself and use individual test methods:
 * @code
 * Tester tester(compare, build, compare, build);  // No callbacks
 * MyKE* ke = allocateKE();
 * MyBlock* input = allocateBlock();
 * // ... allocate other buffers
 * tester.runTestSuiteWithBuffers(KeySize::AES128, builder, enc, dec, ke, input, output, temp);
 * // ... free buffers
 * @endcode
 *
 * @section assumptions Assumptions About User-Provided Functions
 *
 * This framework assumes that user-provided comparison, builder, and memory management
 * functions work correctly. These assumptions include:
 *
 * - **Comparison functions** return true for matching data, false otherwise
 * - **Builder functions** return 0 on success, non-zero on error
 * - **Allocation functions** return valid, initialized pointers or nullptr on failure
 * - **Deallocation functions** nullify the pointer after freeing
 * - **Deallocation functions** handle null pointers gracefully (no-op)
 *
 * Users should test these functions independently before using this framework.
 * The validateMemoryCallbacks() method provides basic sanity checking but is not
 * a substitute for thorough testing of infrastructure code.
 *
 * @section opaque_types Working With Opaque/Incomplete Types
 *
 * This framework is designed to work with opaque pointer types (forward declarations)
 * commonly used in C APIs for encapsulation:
 *
 * @code
 * // In header (opaque)
 * typedef struct KeyExpansion_ KeyExpansion_t;
 * typedef KeyExpansion_t* ptrKeyExpansion_t;
 *
 * // In implementation (complete)
 * struct KeyExpansion_ {
 *     uint32_t* roundKeys;
 *     size_t numRounds;
 * };
 * @endcode
 *
 * Because template code cannot use sizeof() on incomplete types, validation is limited to:
 * - Checking allocation returns non-null
 * - Verifying deallocation nullifies pointers
 * - Testing multiple allocations work
 *
 * Memory access validation (writing to allocated memory) must be done in implementation-
 * specific unit tests where the complete type definition is available. This design
 * respects the encapsulation that opaque types provide and follows industry standards
 * used by libraries like OpenSSL, SQLite, and POSIX FILE*.
 *
 * For comprehensive memory testing, use tools like:
 * - Valgrind (memory leak detection)
 * - AddressSanitizer (out-of-bounds access)
 * - Dr. Memory (Windows memory checking)
 *
 * @section safety Memory Safety
 *
 * When using runTestSuite() with memory callbacks:
 * - Automatic cleanup occurs even if tests throw exceptions
 * - All allocations are checked for null before use
 * - Buffers are freed in reverse allocation order
 *
 * When using runTestSuiteWithBuffers():
 * - User is fully responsible for allocation and deallocation
 * - Framework will not free buffers (caller must do this)
 *
 * @tparam KeyExpansionType Type representing expanded key schedule
 * @tparam BlockType Type representing a cipher block (typically 16 bytes for AES)
 */

namespace CryptoTest {
    namespace BlockCipher {
        template<typename KeyExpansionType, typename BlockType>
        class Tester {
        private:
            TypeByteInterface<KeyExpansionType, BlockType> byteInterface_;
            MemoryCallbacks<KeyExpansionType, BlockType> memoryCallbacks_;

        public:
            /**
             * @brief Constructs an Tester with necessary comparison and builder functions
             *
             * @param compareKE Function that compares a KeyExpansionType with expected byte array
             * @param buildKE Function that builds a KeyExpansionType from key bytes
             * @param compareBlock Function that compares a BlockType with expected byte array
             * @param buildBlock Function that builds a BlockType from raw bytes
             * @param memCallbacks Memory management callbacks for allocation/deallocation
             *
             * @warning All function parameters should be non-null; behavior is undefined if null functions are provided
             * @warning Memory callbacks are required for runTestSuite() method; other methods can work without them
             *
             * @throws std::invalid_argument if memCallbacks is invalid (when used with runTestSuite)
             */
            Tester(
                TypeByteInterface<KeyExpansionType, BlockType> byteOps,
                MemoryCallbacks<KeyExpansionType, BlockType> memCallbacks = {}
            ):
                byteInterface_(byteOps),
                memoryCallbacks_(memCallbacks)
            {}

            /**
             * @brief Run pre-flight checks (optional but recommended)
             */
            bool validateInfrastructure() const {
                bool memValid = memoryCallbacks_.validateMemoryCallbacks();
                bool byteValid = byteInterface_.validateByteOperations();
                return memValid && byteValid;
            }

            /**
             * @brief Tests key expansion building functionality
             *
             * Validates that the key expansion builder correctly generates the round keys
             * from an input key, matching the expected NIST FIPS 197 test vectors. Also
             * tests error handling with invalid key sizes.
             *
             * @param tv Test vector containing input key and expected key expansion
             * @param builder Function under test that performs key expansion
             * @param keBuffer Pre-allocated buffer for key expansion output
             * @return true if all tests pass, false if any test fails
             *
             * @note This function performs critical validation; if it returns false,
             *       subsequent encryption/decryption tests should not be run
             */
            bool testKeyExpansion(
                const ke::TestVector& tv,
                const std::function<int(
                    const unsigned char* const inputKey,
                    size_t keySize,
                    KeyExpansionType* outputExpandedKey
                )> builder,
                KeyExpansionType* const keBuffer
            ) {
                TEST_SUITE("AES Key Expansion Tests");

                int buildStatus = builder(
                    tv.getKey().data(),
                    static_cast<size_t>(tv.getKeySize()),
                    keBuffer
                );

                // Test key expansion building status
                if (!ASSERT_TRUE(
                    buildStatus == 0,
                    "Key expansion should succeed"
                )) {
                    PRINT_RESULTS();
                    return false;  // Critical failure, exit early
                }

                // Verify expanded key matches reference
                ASSERT_TRUE(
                    this->byteInterface_.compareKeyExpansionBytes_(
                        keBuffer,
                        tv.getExpectedExpansion().data()
                    ),
                    "Expanded key should match reference expanded key"
                );

                // Test invalid key length handling
                buildStatus = builder(tv.getKey().data(), 17, keBuffer);
                ASSERT_TRUE(
                    buildStatus != 0,
                    "Invalid key length should return error code"
                );

                PRINT_RESULTS();
                return SUITE_PASSED();
            }

            /**
             * @brief Tests block encryption functionality
             *
             * Validates that the encryption function correctly transforms plaintext to
             * ciphertext using expanded keys, matching NIST FIPS 197 test vectors. Also
             * tests null pointer error handling.
             *
             * @param tv Test vector containing plaintext input and expected ciphertext
             * @param encryptor Function under test that performs block encryption
             * @param keBuffer Pre-allocated buffer for key expansion
             * @param inputBlockBuffer Pre-allocated buffer for input plaintext block
             * @param outputBlockBuffer Pre-allocated buffer for output ciphertext block
             * @return true if all tests pass, false if any test fails
             */
            bool testEncryptBlock(
                const cp::TestVector& tv,
                std::function<int(
                    const BlockType* const inputBlock,
                    const KeyExpansionType* const expandedKey,
                    BlockType* const outputBlock
                )> encryptor,
                KeyExpansionType* const keBuffer,
                BlockType* const inputBlockBuffer,
                BlockType* const outputBlockBuffer
            ) {
                TEST_SUITE("AES Block Encryption Tests");

                // Prepare test environment
                this->byteInterface_.buildKeyExpansionFromBytes_(
                    keBuffer,
                    static_cast<size_t>(tv.getKeySize()),
                                            tv.getKeyExpansion().data()
                );
                this->byteInterface_.buildBlockFromBytes_(inputBlockBuffer, tv.getInput().data());

                // Test single block encryption
                ASSERT_TRUE(
                    encryptor(inputBlockBuffer, keBuffer, outputBlockBuffer) == 0,
                            "AES block encryption should succeed"
                );
                ASSERT_TRUE(
                    this->byteInterface_.compareBlockBytes_(outputBlockBuffer, tv.getExpectedOutput().data()),
                    "Encrypted block should match test vector"
                );

                // Test null pointer handling
                ASSERT_TRUE(
                    encryptor(nullptr, keBuffer, outputBlockBuffer) != 0,
                    "Null input should return error"
                );

                PRINT_RESULTS();
                return SUITE_PASSED();
            }

            /**
             * @brief Tests block decryption functionality
             *
             * Validates that the decryption function correctly transforms ciphertext back
             * to plaintext using expanded keys, matching NIST FIPS 197 test vectors. Also
             * tests null pointer error handling.
             *
             * @param tv Test vector containing ciphertext input and expected plaintext
             * @param decryptor Function under test that performs block decryption
             * @param keBuffer Pre-allocated buffer for key expansion
             * @param inputBlockBuffer Pre-allocated buffer for input ciphertext block
             * @param outputBlockBuffer Pre-allocated buffer for output plaintext block
             * @return true if all tests pass, false if any test fails
             */
            bool testDecryptBlock(
                const cp::TestVector& tv,
                std::function<int(
                    const BlockType* const inputBlock,
                    const KeyExpansionType* const expandedKey,
                    BlockType* const outputBlock
                )> decryptor,
                KeyExpansionType* const keBuffer,
                BlockType* const inputBlockBuffer,
                BlockType* const outputBlockBuffer
            ) {
                TEST_SUITE("AES Block Decryption Tests");

                // Prepare test environment
                this->byteInterface_.buildKeyExpansionFromBytes_(
                    keBuffer,
                    static_cast<size_t>(tv.getKeySize()),
                    tv.getKeyExpansion().data()
                );
                this->byteInterface_.buildBlockFromBytes_(inputBlockBuffer, tv.getInput().data());

                // Test single block decryption
                ASSERT_TRUE(
                    decryptor(inputBlockBuffer, keBuffer, outputBlockBuffer) == 0,
                    "AES block decryption should succeed"
                );
                ASSERT_TRUE(
                    this->byteInterface_.compareBlockBytes_(outputBlockBuffer, tv.getExpectedOutput().data()),
                    "Decrypted block should match test vector"
                );

                // Test null pointer handling
                ASSERT_TRUE(
                    decryptor(nullptr, keBuffer, outputBlockBuffer) != 0,
                    "Null input should return error"
                );

                PRINT_RESULTS();
                return SUITE_PASSED();
            }

            /**
             * @brief Tests encryption-decryption round-trip integrity
             *
             * Validates that encrypting and then decrypting data returns the original
             * plaintext, ensuring that encryption and decryption are proper inverses.
             * This test uses the plaintext from FIPS 197 test vectors as the starting point.
             *
             * @param tv Test vector containing the original plaintext and key
             * @param encryptor Function that performs block encryption
             * @param decryptor Function that performs block decryption
             * @param keBuffer Pre-allocated buffer for key expansion
             * @param inputBlockBuffer Pre-allocated buffer for original plaintext
             * @param encryptedBlockBuffer Pre-allocated buffer for encrypted intermediate result
             * @param decryptedBlockBuffer Pre-allocated buffer for final decrypted result
             * @return true if round-trip preserves data, false otherwise
             *
             * @note This test verifies the fundamental property that D(E(P)) = P,
             *       where D is decryption, E is encryption, and P is plaintext
             */
            bool testEncryptionRoundtrip(
                const cp::TestVector& tv,
                std::function<int(
                    const BlockType* const inputBlock,
                    const KeyExpansionType* const expandedKey,
                    BlockType* const outputBlock
                )> encryptor,
                std::function<int(
                    const BlockType* const inputBlock,
                    const KeyExpansionType* const expandedKey,
                    BlockType* const outputBlock
                )> decryptor,
                KeyExpansionType* const keBuffer,
                BlockType* const inputBlockBuffer,
                BlockType* const encryptedBlockBuffer,
                BlockType* const decryptedBlockBuffer
            ) {
                TEST_SUITE("AES Encryption/Decryption Roundtrip Tests");

                // Prepare test environment with plaintext direction test vector
                cp::TestVector encryptTV(tv.getKeySize(), TestVectors::AES::Direction::Encrypt);

                this->byteInterface_.buildKeyExpansionFromBytes_(
                    keBuffer,
                    static_cast<size_t>(encryptTV.getKeySize()),
                                            encryptTV.getKeyExpansion().data()
                );
                this->byteInterface_.buildBlockFromBytes_(inputBlockBuffer, encryptTV.getInput().data());

                // Perform encryption
                int encryptStatus = encryptor(inputBlockBuffer, keBuffer, encryptedBlockBuffer);
                ASSERT_TRUE(
                    encryptStatus == 0,
                    "Encryption step should succeed"
                );

                // Perform decryption
                int decryptStatus = decryptor(encryptedBlockBuffer, keBuffer, decryptedBlockBuffer);
                ASSERT_TRUE(
                    decryptStatus == 0,
                    "Decryption step should succeed"
                );

                // Verify round-trip integrity
                ASSERT_TRUE(
                    this->byteInterface_.compareBlockBytes_(decryptedBlockBuffer, encryptTV.getInput().data()),
                    "Roundtrip encryption/decryption should preserve original plaintext"
                );

                PRINT_RESULTS();
                return SUITE_PASSED();
            }

            bool validateMemoryCallbacks() {
                return this->memoryCallbacks_.validateMemoryCallbacks();
            }

            /**
             * This version automatically allocates and frees all necessary buffers using the
             * memory callbacks provided in the constructor. This is the recommended method for
             * most users as it eliminates manual buffer management.
             *
             * Executes all test functions (key expansion, encryption, decryption, and
             * round-trip) for a given key size. Stops early if key expansion fails,
             * as subsequent tests would be meaningless.
             *
             * @param keySize The AES key size to test (128, 192, or 256 bits)
             * @param keyBuilder Function that performs key expansion
             * @param encryptor Function that performs block encryption
             * @param decryptor Function that performs block decryption
             * @return true if all tests pass for this key size, false otherwise
             *
             * @throws std::runtime_error if memory callbacks were not provided or are invalid
             * @throws std::bad_alloc if any allocation fails
             *
             * @example
             * @code
             * MemoryCallbacks<MyKE, MyBlock> callbacks{
             *     // Allocate with key size
             *     [](size_t keySizeBits) { return KeyExpansionAlloc(keySizeBits); },
             *     [](MyKE** p) { KeyExpansionDelete(p); },
             *     []() { return BlockMemoryAllocationZero(); },
             *     [](MyBlock** p) { BlockDelete(p); }
             * };
             *
             * Tester<MyKE, MyBlock> tester(compareKE, buildKE, compareBlock, buildBlock, callbacks);
             * bool success = tester.runTestSuite(KeySize::AES128, keyBuilder, encryptor, decryptor);
             * @endcode
             */
            bool runTestSuite(
                TestVectors::AES::KeySize keySize,
                std::function<int(const unsigned char* const, size_t, KeyExpansionType*)> keyBuilder,
                std::function<int(const BlockType* const, const KeyExpansionType* const, BlockType* const)> encryptor,
                std::function<int(const BlockType* const, const KeyExpansionType* const, BlockType* const)> decryptor
            ) {
                // Validate memory callbacks
                if (!this->memoryCallbacks_.isValid()) {
                    throw std::runtime_error(
                        "Memory callbacks not provided. Either:\n"
                        "  1. Provide callbacks in constructor and use this method, or\n"
                        "  2. Use runTestSuiteWithBuffers() and manage memory yourself"
                    );
                }

                const char* keySizeStr = TestVectors::AES::getKeySizeString(keySize);
                bool success = true;

                std::cout << "\n=================================================================" << std::endl;
                std::cout << "==================== AES-" << keySizeStr << " Test Suite ====================" << std::endl;
                std::cout << "=================================================================\n" << std::endl;

                // Allocate all buffers (KeyExpansion needs key size!)
                size_t keySizeBits = static_cast<size_t>(keySize);
                KeyExpansionType* keBuffer = this->memoryCallbacks_.allocateKeyExpansion(keySizeBits);
                BlockType* inputBuffer = this->memoryCallbacks_.allocateBlock();
                BlockType* outputBuffer = this->memoryCallbacks_.allocateBlock();
                BlockType* tempBuffer = this->memoryCallbacks_.allocateBlock();

                // Guard against allocation failures
                if (!keBuffer || !inputBuffer || !outputBuffer || !tempBuffer) {
                    // Clean up any successful allocations
                    if (keBuffer) this->memoryCallbacks_.freeKeyExpansion(&keBuffer);
                    if (inputBuffer) this->memoryCallbacks_.freeBlock(&inputBuffer);
                    if (outputBuffer) this->memoryCallbacks_.freeBlock(&outputBuffer);
                    if (tempBuffer) this->memoryCallbacks_.freeBlock(&tempBuffer);

                    throw std::bad_alloc();
                }

                // Run tests with allocated buffers
                try {
                    // Test key expansion (critical - must pass for other tests to be meaningful)
                    auto keTV = ke::create(keySize);
                    if (!testKeyExpansion(*keTV, keyBuilder, keBuffer)) {
                        std::cout << "\n=== Key expansion failed. Skipping remaining tests for AES-"
                        << keySizeStr << " ===" << std::endl;
                        success = false;
                    } else {
                        // Test encryption
                        auto encTV = cp::create(keySize, TestVectors::AES::Direction::Encrypt);
                        success &= testEncryptBlock(*encTV, encryptor, keBuffer, inputBuffer, outputBuffer);

                        // Test decryption
                        auto decTV = cp::create(keySize, TestVectors::AES::Direction::Decrypt);
                        success &= testDecryptBlock(*decTV, decryptor, keBuffer, inputBuffer, outputBuffer);

                        // Test round-trip
                        success &= testEncryptionRoundtrip(
                            *encTV, encryptor, decryptor, keBuffer, inputBuffer, outputBuffer, tempBuffer
                        );
                    }
                } catch (...) {
                    // Ensure cleanup happens even if tests throw
                    this->memoryCallbacks_.freeKeyExpansion(&keBuffer);
                    this->memoryCallbacks_.freeBlock(&inputBuffer);
                    this->memoryCallbacks_.freeBlock(&outputBuffer);
                    this->memoryCallbacks_.freeBlock(&tempBuffer);
                    throw;
                }

                // Clean up all buffers
                this->memoryCallbacks_.freeKeyExpansion(&keBuffer);
                this->memoryCallbacks_.freeBlock(&inputBuffer);
                this->memoryCallbacks_.freeBlock(&outputBuffer);
                this->memoryCallbacks_.freeBlock(&tempBuffer);

                std::cout << std::endl;
                return success;
            }

            /**
             * @brief Runs complete test suite with user-provided buffers (manual memory management)
             *
             * This is an alternative to runTestSuite() that lets users manage memory themselves.
             * Useful when you want fine control over allocation strategy, need to reuse buffers
             * across multiple test runs, or want to avoid std::function overhead.
             *
             * @param keySize The AES key size to test (128, 192, or 256 bits)
             * @param keyBuilder Function that performs key expansion
             * @param encryptor Function that performs block encryption
             * @param decryptor Function that performs block decryption
             * @param keBuffer Pre-allocated buffer for key expansion
             * @param inputBuffer Pre-allocated buffer for input blocks
             * @param outputBuffer Pre-allocated buffer for output blocks
             * @param tempBuffer Pre-allocated buffer for intermediate results (round-trip test)
             * @return true if all tests pass for this key size, false otherwise
             *
             * @note The buffers should be sized appropriately for the largest key size
             *       and block size to avoid reallocation between test runs
             * @note User is responsible for allocating buffers before calling and freeing after
             */
            bool runTestSuiteWithBuffers(
                TestVectors::AES::KeySize keySize,
                std::function<int(const unsigned char* const, size_t, KeyExpansionType*)> keyBuilder,
                std::function<int(const BlockType* const, const KeyExpansionType* const, BlockType* const)> encryptor,
                std::function<int(const BlockType* const, const KeyExpansionType* const, BlockType* const)> decryptor,
                KeyExpansionType* const keBuffer,
                BlockType* const inputBuffer,
                BlockType* const outputBuffer,
                BlockType* const tempBuffer
            ) {
                const char* keySizeStr = TestVectors::AES::getKeySizeString(keySize);
                bool success = true;

                std::cout << "\n=================================================================" << std::endl;
                std::cout << "==================== AES-" << keySizeStr << " Test Suite ====================" << std::endl;
                std::cout << "=================================================================\n" << std::endl;

                // Test key expansion (critical - must pass for other tests to be meaningful)
                auto keTV = ke::create(keySize);
                if (!testKeyExpansion(*keTV, keyBuilder, keBuffer)) {
                    std::cout << "\n=== Key expansion failed. Skipping remaining tests for AES-"
                    << keySizeStr << " ===" << std::endl;
                    return false;
                }

                // Test encryption
                auto encTV = cp::create(keySize, TestVectors::AES::Direction::Encrypt);
                success &= testEncryptBlock(*encTV, encryptor, keBuffer, inputBuffer, outputBuffer);

                // Test decryption
                auto decTV = cp::create(keySize, TestVectors::AES::Direction::Decrypt);
                success &= testDecryptBlock(*decTV, decryptor, keBuffer, inputBuffer, outputBuffer);

                // Test round-trip
                success &= testEncryptionRoundtrip(
                    *encTV, encryptor, decryptor, keBuffer, inputBuffer, outputBuffer, tempBuffer
                );

                std::cout << std::endl;
                return success;
            }
        }; // Tester
    } // BlockCipher
} // CryptoTest

#endif // BLOCK_CIPHER_TESTER_HPP
