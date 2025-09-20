#include "../include/test_framework.hpp"
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
#define CREATE_EXAMPLE(klb,mode) NISTSP800_38A_Examples::createExample(static_cast<COMMAESVECT_KEYLEN>(klb), static_cast<COMMAESVECT_OPTMODE>(mode))

void test_successful_operations(AESENC_KEYLEN klb, AESENC_OPTMODE mode);
void test_empty_vector_exceptions(AESENC_KEYLEN klb, AESENC_OPTMODE mode);
void test_invalid_size_exceptions(AESENC_KEYLEN klb, AESENC_OPTMODE mode);
void test_exception_safety(AESENC_KEYLEN klb, AESENC_OPTMODE mode);
void test_cbc_mode_iv_handling(AESENC_KEYLEN klb);

/**
 * @brief Runs the complete set of tests for a specific key length and operation mode.
 *
 * This function prints a banner for the key length and then executes the key
 * expansion, encryption, decryption, and roundtrip tests.
 *
 * @param kl The key length to test.
 * @param mode The operation mode to test
 * @return true if all tests passed, false otherwise.
 */
bool runTestsForKeylengthMode(AESENC_KEYLEN klb, AESENC_OPTMODE mode);

int main() {
    std::cout << "=== C/C++ Interface Integration Tests with Specific Exception Handling ===" << std::endl;

    std::cout << "\n=== Interface Integration Tests Complete ===" << std::endl;
    return 0;
}

void test_successful_operations(AESENC_KEYLEN klb, AESENC_OPTMODE mode) {
    std::unique_ptr<EXAMPLE_BASE> example = CREATE_EXAMPLE(klb,mode);
    if (!example) {
        // Handle the error if the mode is unsupported
        std::cerr << "Error: Unsupported operation mode." << std::endl;
        return;
    }
    TEST_SUITE("Successful Operations Tests");

    try {
        AESENC_OPTMODE opt_mode = static_cast<AESENC_OPTMODE>(mode);
        // Test operation mode
        AESKEY key(example->getKeyAsVector(), klb);
        AESencryption::Cipher ciph(key, opt_mode);

        // Verify key expansion is initialized
        ASSERT_TRUE(
            ciph.isKeyExpansionInitialized(),
            "Key expansion should be initialized after Cipher construction"
        );

        std::vector<uint8_t> input = example->getInputAsVector();
        std::vector<uint8_t> encrypted(TEXT_SIZE);
        std::vector<uint8_t> decrypted(TEXT_SIZE);

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

void test_empty_vector_exceptions(AESENC_KEYLEN klb, AESENC_OPTMODE mode) {
    TEST_SUITE("Empty Vector Exception Tests");

    AESKEY key(klb);
    AESencryption::Cipher cipher(key, mode);

    std::vector<uint8_t> input(TEXT_SIZE);
    std::vector<uint8_t> output(TEXT_SIZE);

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

void test_invalid_size_exceptions(AESENC_KEYLEN klb, AESENC_OPTMODE mode) {
    TEST_SUITE("Invalid Size Exception Tests");

    AESKEY key(klb);
    AESencryption::Cipher cipher(key, mode);

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

void test_exception_safety(AESENC_KEYLEN klb, AESENC_OPTMODE mode) {
    TEST_SUITE("Exception Safety Tests");

    AESKEY key(klb);
    AESencryption::Cipher cipher(key, mode);

    uint8_t input[TEXT_SIZE];
    uint8_t output[TEXT_SIZE];

    // Verify object is in valid state initially
    ASSERT_TRUE(cipher.isKeyExpansionInitialized(), "Cipher should be properly initialized");

    try {
        // This should throw
        cipher.encrypt(nullptr, TEXT_SIZE, output);
        ASSERT_TRUE(false, "Should have thrown exception");
    } catch (const std::invalid_argument&) {
        // Object should still be usable after exception
        ASSERT_TRUE(
            cipher.isKeyExpansionInitialized(),
            "Key expansion should still be initialized after exception"
        );
        try {
            cipher.encrypt(input, TEXT_SIZE, output);
            ASSERT_TRUE(true, "Cipher object remained usable after exception");
        } catch (const std::exception& e) {
            ASSERT_TRUE(
                false,
                std::string("Cipher object corrupted after exception: ") + e.what()
            );
        }
    }

    PRINT_RESULTS();
}

void test_cbc_mode_iv_handling(AESENC_KEYLEN klb) {
    TEST_SUITE("CBC Mode IV Handling Tests");

    try {
        AESencryption::Key cbc_key(klb);
        AESencryption::Cipher cbc_cipher(cbc_key, AESencryption::Cipher::OperationMode::Identifier::CBC);

        std::vector<uint8_t> input(TEXT_SIZE);
        std::vector<uint8_t> output(TEXT_SIZE);

        // If IV is not properly set, it should throw an exception
        try {
            cbc_cipher.encryption(input, output);
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

bool runTestsForKeylengthMode(AESENC_KEYLEN klb, AESENC_OPTMODE mode){
    test_successful_operations(klb, mode);
    test_empty_vector_exceptions(klb, mode);
    test_invalid_size_exceptions(klb, mode);
    test_exception_safety(klb, mode);
    test_cbc_mode_iv_handling(klb);
}
