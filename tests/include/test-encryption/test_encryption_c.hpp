/**
 * @file test_encryption_c.hpp
 * @brief Template-based testing framework for C-style symmetric encryption functions
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
 * EncryptionTester<MyKeyExpansion, MyBlock> tester(compareKE, buildKE, compareBlock, buildBlock);
 *
 * // Run tests with NIST test vectors
 * auto tv = TestVectors::AES::FIPS197::Cipher::create(KeySize::AES128);
 * MyKeyExpansion ke_buffer;
 * MyBlock input_buffer, output_buffer;
 * bool success = tester.testEncryptBlock(*tv, myEncryptFunc, &ke_buffer, &input_buffer, &output_buffer);
 * @endcode
 */

#ifndef TEST_ENCRYPTION_C_HPP
#define TEST_ENCRYPTION_C_HPP

#include "../test-vectors/fips197_key_expansion.hpp"
#include "../test-vectors/fips197_cipher.hpp"
#include "../test_framework.hpp"
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
 * - Pre-allocated buffers to avoid memory allocation during tests
 * - Consistent error conventions (0 = success, non-zero = failure)
 * - Integration with existing test framework macros (TEST_SUITE, ASSERT_TRUE, etc.)
 * - Support for NIST FIPS 197 test vectors
 *
 * @tparam KeyExpansionType Type representing expanded key schedule
 * @tparam BlockType Type representing a cipher block (typically 16 bytes for AES)
 */
template<typename KeyExpansionType, typename BlockType>
class EncryptionTester {
private:
    /// Function to compare key expansion with expected bytes
    const std::function<bool(
        const KeyExpansionType* const,
        size_t keySize,
        const unsigned char* const
    )> compareKeyExpansionBytes_;

    /// Function to build key expansion from raw key bytes
    const std::function<int(
        KeyExpansionType* const,
        size_t keySize,
        const unsigned char* const
    )> buildKeyExpansionFromBytes_;

    /// Function to compare block with expected bytes
    const std::function<bool(
        const BlockType* const,
        const unsigned char* const
    )> compareBlockBytes_;

    /// Function to build block from raw bytes
    const std::function<int(
        BlockType* const,
        const unsigned char* const
    )> buildBlockFromBytes_;

public:
    /**
     * @brief Constructs an EncryptionTester with necessary comparison and builder functions
     *
     * @param compareKE Function that compares a KeyExpansionType with expected byte array
     * @param buildKE Function that builds a KeyExpansionType from key bytes
     * @param compareBlock Function that compares a BlockType with expected byte array
     * @param buildBlock Function that builds a BlockType from raw bytes
     *
     * @note All function parameters should be non-null; behavior is undefined if null functions are provided
     */
    EncryptionTester(
        std::function<bool(const KeyExpansionType* const, size_t, const unsigned char* const)> compareKE,
                     std::function<int(KeyExpansionType* const, size_t, const unsigned char* const)> buildKE,
                     std::function<bool(const BlockType* const, const unsigned char* const)> compareBlock,
                     std::function<int(BlockType* const, const unsigned char* const)> buildBlock
    ) : compareKeyExpansionBytes_(compareKE),
    buildKeyExpansionFromBytes_(buildKE),
    compareBlockBytes_(compareBlock),
    buildBlockFromBytes_(buildBlock)
    {}

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
            compareKeyExpansionBytes_(
                keBuffer,
                static_cast<size_t>(tv.getKeySize()),
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
        buildKeyExpansionFromBytes_(
            keBuffer,
            static_cast<size_t>(tv.getKeySize()),
                                    tv.getKeyExpansion().data()
        );
        buildBlockFromBytes_(inputBlockBuffer, tv.getInput().data());

        // Test single block encryption
        ASSERT_TRUE(
            encryptor(inputBlockBuffer, keBuffer, outputBlockBuffer) == 0,
                    "AES block encryption should succeed"
        );

        ASSERT_TRUE(
            compareBlockBytes_(outputBlockBuffer, tv.getExpectedOutput().data()),
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
        buildKeyExpansionFromBytes_(
            keBuffer,
            static_cast<size_t>(tv.getKeySize()),
                                    tv.getKeyExpansion().data()
        );
        buildBlockFromBytes_(inputBlockBuffer, tv.getInput().data());

        // Test single block decryption
        ASSERT_TRUE(
            decryptor(inputBlockBuffer, keBuffer, outputBlockBuffer) == 0,
                    "AES block decryption should succeed"
        );

        ASSERT_TRUE(
            compareBlockBytes_(outputBlockBuffer, tv.getExpectedOutput().data()),
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

        buildKeyExpansionFromBytes_(
            keBuffer,
            static_cast<size_t>(encryptTV.getKeySize()),
                                    encryptTV.getKeyExpansion().data()
        );
        buildBlockFromBytes_(inputBlockBuffer, encryptTV.getInput().data());

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
            compareBlockBytes_(decryptedBlockBuffer, encryptTV.getInput().data()),
                    "Roundtrip encryption/decryption should preserve original plaintext"
        );

        PRINT_RESULTS();
        return SUITE_PASSED();
    }

    /**
     * @brief Runs complete test suite for a specific key size
     *
     * Executes all test functions (key expansion, encryption, decryption, and
     * round-trip) for a given key size. Stops early if key expansion fails,
     * as subsequent tests would be meaningless.
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
     */
    bool runTestSuite(
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
};

#endif // TEST_ENCRYPTION_C_HPP
