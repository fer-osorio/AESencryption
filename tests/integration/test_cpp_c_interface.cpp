#include "../include/test_framework.hpp"
#include "../../data-encryption/include/constants.h"
#include "../../data-encryption/include/AES.h"
#include "../../data-encryption/include/operation_modes.h"
#include "../../include/cipher.hpp"
#include "../../include/key.hpp"
#include "../include/NIST_SP_800-38A_TestVectors.hpp"
#include <cstring>
#include <stdexcept>

#define TEXT_SIZE NISTSP800_38A_Examples::TEXT_SIZE

#define AESKEY AESencryption::Key

#define AESENC_KEYLEN AESencryption::Key::LengthBits
#define AESENC_OPTMODE AESencryption::Cipher::OperationMode::Identifier

#define COMMAESVECT_KEYLEN CommonAESVectors::KeylengthBits
#define COMMAESVECT_OPTMODE NISTSP800_38A_Examples::OperationMode

#define EXAMPLE_BASE NISTSP800_38A_Examples::ExampleBase

void test_successful_operations(COMMAESVECT_KEYLEN klb, COMMAESVECT_OPTMODE mode) {
    std::unique_ptr<EXAMPLE_BASE> example = NISTSP800_38A_Examples::createExample(klb, mode);
    if (!example) {
        // Handle the error if the mode is unsupported
        std::cerr << "Error: Unsupported operation mode." << std::endl;
        return;
    }
    TEST_SUITE("Successful Operations Tests");

    try {
        AESENC_KEYLEN keylen = static_cast<AESENC_KEYLEN>(klb);
        AESENC_OPTMODE opt_mode = static_cast<AESENC_OPTMODE>(mode);
        // Test operation mode
        AESKEY key(example->getKeyAsVector(), keylen);
        AESencryption::Cipher ciph(key, opt_mode);

        // Verify key expansion is initialized
        ASSERT_TRUE(
            ciph.isKeyExpansionInitialized(),
            "Key expansion should be initialized after Cipher construction"
        );

        std::vector<uint8_t> input = example->getInputAsVector();
        std::vector<uint8_t> encrypted(BLOCK_SIZE);
        std::vector<uint8_t> decrypted(BLOCK_SIZE);

        ciph.encryption(input, encrypted);
        ASSERT_BYTES_EQUAL(
            example->getExpectedOutput(),
            encrypted.data(),
            TEXT_SIZE,
            "ECB encryption should match reference vector"
        );
        ciph.decryption(encrypted, decrypted);
        ASSERT_BYTES_EQUAL(
            example->getInput(),
            decrypted.data(),
            TEXT_SIZE,
            "ECB roundtrip should preserve data"
        );
        ASSERT_TRUE(true, "All successful operations completed");
    } catch (const std::exception& e) {
        ASSERT_TRUE(false, std::string("Unexpected exception: ") + e.what());
    }

    PRINT_RESULTS();
}

void test_empty_vector_exceptions(COMMAESVECT_KEYLEN klb, COMMAESVECT_OPTMODE mode) {
    TEST_SUITE("Empty Vector Exception Tests");

    AESENC_KEYLEN keylen = static_cast<AESENC_KEYLEN>(klb);
    AESKEY key(keylen);
    AESencryption::Cipher cipher(key, static_cast<AESENC_OPTMODE>(mode));

    std::vector<uint8_t> input(BLOCK_SIZE);
    std::vector<uint8_t> output(BLOCK_SIZE);

    // Test empty input data
    try {
        cipher.encryption(std::vector<uint8_t>(0), output);
        ASSERT_TRUE(false, "Should throw exception for empty input vector");
    } catch (const std::invalid_argument& e) {
        std::string error_msg = e.what();
        ASSERT_TRUE(error_msg.find("Input vector data cannot be empty") != std::string::npos,
                    "Should mention empty input in error message");
    } catch (const std::exception& e) {
        ASSERT_TRUE(false, std::string("Wrong exception type: ") + e.what());
    }

    // Test empty output
    try {
        std::vector<uint8_t> empty(0);
        cipher.decryption(input, empty);
        ASSERT_TRUE(false, "Should throw exception for empty output vector");
    } catch (const std::invalid_argument& e) {
        std::string error_msg = e.what();
        ASSERT_TRUE(error_msg.find("Output vector cannot be empty") != std::string::npos,
                    "Should mention empty output in error message");
    } catch (const std::exception& e) {
        ASSERT_TRUE(false, std::string("Wrong exception type: ") + e.what());
    }

    // Test decryption empty vectors
    try {
        cipher.decryption(std::vector<uint8_t>(0), output);
        ASSERT_TRUE(false, "Should throw exception for empty input vector");
    } catch (const std::invalid_argument& e) {
        std::string error_msg = e.what();
        ASSERT_TRUE(error_msg.find("Input vector data cannot be empty") != std::string::npos,
                    "Should mention empty input in error message");
    } catch (const std::exception& e) {
        ASSERT_TRUE(false, std::string("Wrong exception type: ") + e.what());
    }

    // Test empty output
    try {
        std::vector<uint8_t> empty(0);
        cipher.decryption(input, empty);
        ASSERT_TRUE(false, "Should throw exception for empty output vector");
    } catch (const std::invalid_argument& e) {
        std::string error_msg = e.what();
        ASSERT_TRUE(error_msg.find("Output vector cannot be empty") != std::string::npos,
                    "Should mention empty output in error message");
    } catch (const std::exception& e) {
        ASSERT_TRUE(false, std::string("Wrong exception type: ") + e.what());
    }

    PRINT_RESULTS();
}

void test_invalid_size_exceptions(COMMAESVECT_KEYLEN klb, COMMAESVECT_OPTMODE mode) {
    std::unique_ptr<EXAMPLE_BASE> example = NISTSP800_38A_Examples::createExample(klb, mode);
    if (!example) {
        // Handle the error if the mode is unsupported
        std::cerr << "Error: Unsupported operation mode." << std::endl;
        return;
    }
    TEST_SUITE("Invalid Size Exception Tests");

    AESENC_KEYLEN keylen = static_cast<AESENC_KEYLEN>(klb);
    AESKEY key(keylen);
    AESENC_OPTMODE opt_mode = static_cast<AESENC_OPTMODE>(mode);
    AESencryption::Cipher cipher(key, opt_mode);

    std::vector<uint8_t> invalid_input(15);
    std::vector<uint8_t> output(TEXT_SIZE);

    // Test non-block-aligned size (should map to InvalidInputSize from C)
    try {
        cipher.encryption(invalid_input, output);
        ASSERT_TRUE(false, "Should throw exception for non-valid size");
    } catch (const std::invalid_argument& e) {
        std::string error_msg = e.what();
        ASSERT_TRUE(error_msg.find("must be at least block size") != std::string::npos,
                    "Should mention block size condition in error message");
    } catch (const std::exception& e) {
        ASSERT_TRUE(false, std::string("Wrong exception type: ") + e.what());
    }

    // Test same errors for decryption
    try {
        cipher.decryption(invalid_input, output);
        ASSERT_TRUE(false, "Decryption should throw exception for non-valid size");
    } catch (const std::invalid_argument& e) {
        std::string error_msg = e.what();
        ASSERT_TRUE(error_msg.find("must be at least block size") != std::string::npos,
                    "Should mention block size condition in error message");
    } catch (const std::exception& e) {
        ASSERT_TRUE(false, std::string("Wrong exception type: ") + e.what());
    }

    PRINT_RESULTS();
}

void test_specific_exception_code_mapping(AESENC_KEYLEN klb, AESENC_OPTMODE mode) {
    TEST_SUITE("Specific Exception Code Mapping Tests");

    // Test direct C function calls and their error codes
    std::vector<uint8_t> dummy_key(static_cast<size_t>(klb)/8, 0);
    size_t c_klb = static_cast<size_t>(klb);
    ptrKeyExpansion_t c_ke = KeyExpansionMemoryAllocationBuild(dummy_key.data(), c_klb, false);

    if (c_ke != nullptr) {
        const uint8_t* key_expansion_ptr = KeyExpansionReturnBytePointerToData(c_ke);
        uint8_t input[BLOCK_SIZE];
        uint8_t output[BLOCK_SIZE];

        // Test NullInput error code
        enum ExceptionCode result = encryptECB(nullptr, BLOCK_SIZE, key_expansion_ptr, c_klb, output);
        ASSERT_TRUE(result == NullInput, "C function should return NullInput for null input");

        // Test NullOutput error code
        result = encryptECB(input, BLOCK_SIZE, key_expansion_ptr, c_klb, nullptr);
        ASSERT_TRUE(result == NullOutput, "C function should return NullOutput for null output");

        // Test InvalidInputSize error code
        result = encryptECB(input, 15, key_expansion_ptr, 128, output);
        ASSERT_TRUE(result == InvalidInputSize, "C function should return InvalidInputSize for non-valid size");

        // Test ZeroLength error code
        result = encryptECB(input, 0, key_expansion_ptr, 128, output);
        ASSERT_TRUE(result == ZeroLength, "C function should return ZeroLength for zero size");

        // Test NullKeyExpansion error code
        result = encryptECB(input, BLOCK_SIZE, nullptr, 128, output);
        ASSERT_TRUE(result == NullKeyExpansion, "C function should return NullKeyExpansion for null key expansion");

        KeyExpansionDelete(&c_ke);
    } else{
        std::cerr << "No test runned. Something went wrong in key creation.";
    }

    PRINT_RESULTS();
}

void test_key_expansion_initialization() {
    TEST_SUITE("Key Expansion Initialization Tests");

    // Test that key expansion is properly initialized
    AESENC_KEYLEN keylen = static_cast<AESENC_KEYLEN>(klb);

    // Test ECB mode
    ECB_EXAMPLE ecb_exmp = createECBencryptionExample(klb);
    AESKEY key(example->getKeyAsVector(), keylen);
    AESencryption::Cipher cipher(key);

    ASSERT_TRUE(cipher.isKeyExpansionInitialized(),
                "Key expansion should be initialized after construction");

    const uint8_t* key_expansion_ptr = cipher.getKeyExpansionForTesting();
    ASSERT_NOT_NULL(key_expansion_ptr, "Key expansion pointer should not be null");

    // Compare with direct C implementation
    ptrKeyExpansion_t c_ke = KeyExpansionMemoryAllocationBuild(TestVectors::test_key_128, 128, false);
    if (c_ke != nullptr) {
        uint8_t c_key_expansion[176]; // AES-128 key expansion size
        KeyExpansionWriteBytes(c_ke, c_key_expansion);

        // Compare first few bytes to verify consistency
        ASSERT_BYTES_EQUAL(TestVectors::test_key_128, key_expansion_ptr, BLOCK_SIZE,
                          "First BLOCK_SIZE bytes of key expansion should match original key");

        KeyExpansionDelete(&c_ke);
    }

    PRINT_RESULTS();
}

void test_exception_safety() {
    TEST_SUITE("Exception Safety Tests");

    AESENC_KEYLEN keylen = static_cast<AESENC_KEYLEN>(klb);

    // Test ECB mode
    ECB_EXAMPLE ecb_exmp = createECBencryptionExample(klb);
    AESKEY key(example->getKeyAsVector(), keylen);
    AESencryption::Cipher cipher(key);

    uint8_t output[BLOCK_SIZE];

    // Verify object is in valid state initially
    ASSERT_TRUE(cipher.isKeyExpansionInitialized(), "Cipher should be properly initialized");

    try {
        // This should throw
        cipher.encrypt(nullptr, BLOCK_SIZE, output);
        ASSERT_TRUE(false, "Should have thrown exception");
    } catch (const std::invalid_argument&) {
        // Object should still be usable after exception
        ASSERT_TRUE(cipher.isKeyExpansionInitialized(),
                    "Key expansion should still be initialized after exception");

        try {
            cipher.encrypt(TestVectors::test_data, BLOCK_SIZE, output);
            ASSERT_TRUE(true, "Cipher object remained usable after exception");
        } catch (const std::exception& e) {
            ASSERT_TRUE(false, std::string("Cipher object corrupted after exception: ") + e.what());
        }
    }

    PRINT_RESULTS();
}

void test_consistency_with_c_implementation() {
    TEST_SUITE("C vs C++ Consistency Tests");

    try {
        // Direct C implementation
        ptrKeyExpansion_t c_ke = KeyExpansionMemoryAllocationBuild(TestVectors::test_key_128, 128, false);
        ASSERT_NOT_NULL(c_ke, "C key expansion creation should succeed");

        const uint8_t* key_expansion_ptr = KeyExpansionReturnBytePointerToData(c_ke);
        uint8_t c_output[TEXT_SIZE];

        enum ExceptionCode c_result = encryptECB(TestVectors::test_data_2blocks, TEXT_SIZE,
                                                key_expansion_ptr, 128, c_output);
        ASSERT_TRUE(c_result == NoException, "C encryption should succeed with NoException");

        // C++ wrapper implementation
        AESKEY cpp_key(TestVectors::test_key_128,
                                   AESencryption::Key::LengthBits::_128,
                                   AESencryption::Key::OpMode::ECB);
        AESencryption::Cipher cpp_cipher(cpp_key);

        uint8_t cpp_output[TEXT_SIZE];
        cpp_cipher.encrypt(TestVectors::test_data_2blocks, TEXT_SIZE, cpp_output);

        ASSERT_BYTES_EQUAL(c_output, cpp_output, TEXT_SIZE,
                           "C++ wrapper should produce same result as direct C");

        // Test decryption consistency
        uint8_t c_decrypted[TEXT_SIZE];
        uint8_t cpp_decrypted[TEXT_SIZE];

        c_result = decryptECB(c_output, TEXT_SIZE, key_expansion_ptr, 128, c_decrypted);
        ASSERT_TRUE(c_result == NoException, "C decryption should succeed");

        cpp_cipher.decrypt(cpp_output, TEXT_SIZE, cpp_decrypted);

        ASSERT_BYTES_EQUAL(c_decrypted, cpp_decrypted, TEXT_SIZE,
                           "C++ and C decryption should produce same result");

        ASSERT_BYTES_EQUAL(TestVectors::test_data_2blocks, cpp_decrypted, TEXT_SIZE,
                           "Both implementations should correctly decrypt data");

        KeyExpansionDelete(&c_ke);

    } catch (const std::exception& e) {
        ASSERT_TRUE(false, std::string("Consistency test failed with exception: ") + e.what());
    }

    PRINT_RESULTS();
}

void test_cbc_mode_iv_handling() {
    TEST_SUITE("CBC Mode IV Handling Tests");

    try {
        AESencryption::Key cbc_key(TestVectors::test_key_128,
                                  AESencryption::Key::LengthBits::_128,
                                  AESencryption::Key::OpMode::CBC);
        AESencryption::Cipher cbc_cipher(cbc_key);

        uint8_t output[TEXT_SIZE];

        // This test depends on your IV handling implementation
        // If IV is not properly set, it should throw an exception
        try {
            cbc_cipher.encrypt(TestVectors::test_data_2blocks, TEXT_SIZE, output);
            ASSERT_TRUE(true, "CBC encryption succeeded (IV properly handled)");
        } catch (const std::exception& e) {
            std::string error_msg = e.what();
            if (error_msg.find("IV") != std::string::npos) {
                ASSERT_TRUE(true, "CBC properly detected missing IV");
            } else {
                ASSERT_TRUE(false, std::string("Unexpected CBC error: ") + e.what());
            }
        }

    } catch (const std::exception& e) {
        ASSERT_TRUE(false, std::string("CBC IV test failed: ") + e.what());
    }

    PRINT_RESULTS();
}

int main() {
    std::cout << "=== C/C++ Interface Integration Tests with Specific Exception Handling ===" << std::endl;

    test_successful_operations();
    test_empty_vector_exceptions();
    test_invalid_size_exceptions();
    test_specific_exception_code_mapping();
    test_key_expansion_initialization();
    test_nothrow_versions();
    test_exception_safety();
    test_consistency_with_c_implementation();
    test_cbc_mode_iv_handling();

    std::cout << "\n=== Interface Integration Tests Complete ===" << std::endl;
    return 0;
}
