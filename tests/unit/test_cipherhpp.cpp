#include "../include/test_framework.hpp"
#include "../include/NIST_SP_800-38A_TestVectors.hpp"
#include "../../include/cipher.hpp"

#define AESKEY AESencryption::Key
#define AESKEY_LENBITS AESencryption::Key::LengthBits

#define AESCIPHER AESencryption::Cipher
#define AESCIPHER_OPTMODE AESencryption::Cipher::OperationMode::Identifier

bool test_successful_operations(AESKEY_LENBITS klb, AESCIPHER_OPTMODE mode);
bool test_empty_vector_exceptions(AESKEY_LENBITS klb, AESCIPHER_OPTMODE mode);
bool test_invalid_size_exceptions(AESKEY_LENBITS klb, AESCIPHER_OPTMODE mode);
bool test_exception_safety(AESKEY_LENBITS klb, AESCIPHER_OPTMODE mode);
bool test_cbc_mode_iv_handling(AESKEY_LENBITS klb);

/**
 * @brief Runs the complete set of tests for a specific key length and operation mode.
 *
 * This function prints a banner for the key length and then executes the tests for cipher object.
 *
 * @param kl The key length to test.
 * @param mode The operation mode to test
 * @return true if all tests passed, false otherwise.
 */
bool runTestsForKeylengthMode(AESKEY_LENBITS klb, AESCIPHER_OPTMODE mode);

int main() {
    std::cout << "=== C/C++ Cipher.hpp Tests with Specific Exception Handling ===" << std::endl;
    std::vector<AESKEY_LENBITS> keylengths = { AESKEY_LENBITS::_128, AESKEY_LENBITS::_192, AESKEY_LENBITS::_256 };
    std::vector<AESCIPHER_OPTMODE> optModes = { AESCIPHER_OPTMODE::ECB, AESCIPHER_OPTMODE::CBC };
    bool success = true;

    for(AESKEY_LENBITS klb: keylengths){
        for(AESCIPHER_OPTMODE mode: optModes){
            success &= runTestsForKeylengthMode(klb,mode);
        }
    }

    if(success){
        std::cout << "\n===================== All Cipher.hpp Tests Succeed =====================" << std::endl;
        return 0;
    } else {
        std::cout << "\n===================== Some Cipher.hpp Tests Failed =====================" << std::endl;
        return 1;
    }
}

bool test_successful_operations(AESKEY_LENBITS klb, AESCIPHER_OPTMODE mode) {
    NIST_EXAMPLEBASE_UPTR example = NIST_CREATEEXAMPLE(klb,mode);
    if (!example) {
        // Handle the error if the mode is unsupported
        std::cerr << "Error: Unsupported operation mode." << std::endl;
        return false;
    }
    TEST_SUITE("Successful Operations Tests");
    bool success = true;
    std::string optModeStr = NIST_GETMODESTRING(mode);

    try {
        // Test operation mode
        AESKEY key(example->getKeyAsVector(), klb);
        AESCIPHER ciph(key, mode);
        ciph.setInitialVectorForTesting(std::vector<uint8_t>(NIST::getInitializationVectorAsStdVector()));

        // Verify key expansion is initialized
        success &= ASSERT_TRUE(
            ciph.isKeyExpansionInitialized(),
            "Key expansion should be initialized after Cipher construction"
        );

        std::vector<uint8_t> input = example->getInputAsVector();
        std::vector<uint8_t> encrypted(NIST_TEXTSIZE);
        std::vector<uint8_t> decrypted(NIST_TEXTSIZE);

        ciph.encryption(input, encrypted);
        success &= ASSERT_BYTES_EQUAL(
            example->getExpectedOutput(),
            encrypted.data(),
            NIST_TEXTSIZE,
            optModeStr + " encryption should match reference vector"
        );
        ciph.decryption(encrypted, decrypted);
        success &= ASSERT_BYTES_EQUAL(
            example->getInput(),
            decrypted.data(),
            NIST_TEXTSIZE,
            optModeStr + " roundtrip should preserve data"
        );
        success &= ASSERT_TRUE(true, "All successful operations completed");
    } catch (const std::exception& e) {
        success &= ASSERT_TRUE(false, std::string("Unexpected exception: ") + e.what());
    }
    PRINT_RESULTS();
    return success;
}

bool test_empty_vector_exceptions(AESKEY_LENBITS klb, AESCIPHER_OPTMODE mode) {
    TEST_SUITE("Empty Vector Exception Tests");
    bool success = true;

    AESKEY key(klb);
    AESCIPHER cipher(key, mode);

    std::vector<uint8_t> input(NIST_TEXTSIZE);
    std::vector<uint8_t> output(NIST_TEXTSIZE);
    std::vector<uint8_t> empty(0);

    // Test empty input data
    try {
        cipher.encryption(empty, output);
        success &= ASSERT_TRUE(false, "Should throw exception for empty input vector");
    } catch (const std::invalid_argument& e) {
        std::string error_msg = e.what();
        success &= ASSERT_TRUE(error_msg.find("Input data vector cannot be empty") != std::string::npos,
                    "Should mention empty input in error message");
    } catch (const std::exception& e) {
        success &= ASSERT_TRUE(false, std::string("Wrong exception type: ") + e.what());
    }

    // Test empty output
    try {
        cipher.decryption(input, empty);
        success &= ASSERT_TRUE(false, "Should throw exception for empty output vector");
    } catch (const std::invalid_argument& e) {
        std::string error_msg = e.what();
        success &= ASSERT_TRUE(error_msg.find("Output data vector cannot be empty") != std::string::npos,
                    "Should mention empty output in error message");
    } catch (const std::exception& e) {
        success &= ASSERT_TRUE(false, std::string("Wrong exception type: ") + e.what());
    }

    // Test decryption empty vectors
    try {
        cipher.decryption(std::vector<uint8_t>(0), output);
        success &= ASSERT_TRUE(false, "Should throw exception for empty input vector");
    } catch (const std::invalid_argument& e) {
        std::string error_msg = e.what();
        success &= ASSERT_TRUE(error_msg.find("Input data vector cannot be empty") != std::string::npos,
                    "Should mention empty input in error message");
    } catch (const std::exception& e) {
        success &= ASSERT_TRUE(false, std::string("Wrong exception type: ") + e.what());
    }

    // Test empty output
    try {
        cipher.decryption(input, empty);
        success &= ASSERT_TRUE(false, "Should throw exception for empty output vector");
    } catch (const std::invalid_argument& e) {
        std::string error_msg = e.what();
        success &= ASSERT_TRUE(error_msg.find("Output data vector cannot be empty") != std::string::npos,
                    "Should mention empty output in error message");
    } catch (const std::exception& e) {
        success &= ASSERT_TRUE(false, std::string("Wrong exception type: ") + e.what());
    }
    PRINT_RESULTS();
    return success;
}

bool test_invalid_size_exceptions(AESKEY_LENBITS klb, AESCIPHER_OPTMODE mode) {
    TEST_SUITE("Invalid Size Exception Tests");
    bool success = true;

    AESKEY key(klb);
    AESCIPHER cipher(key, mode);

    std::vector<uint8_t> invalid_input(15);
    std::vector<uint8_t> output(NIST_TEXTSIZE);

    // Test non-block-aligned size (should map to InvalidInputSize from C)
    try {
        cipher.encryption(invalid_input, output);
        success &= ASSERT_TRUE(false, "Should throw exception for non-valid size");
    } catch (const std::invalid_argument& e) {
        std::string error_msg = e.what();
        success &= ASSERT_TRUE(error_msg.find("must be at least one block size") != std::string::npos,
                    "Should mention block size condition in error message");
    } catch (const std::exception& e) {
        success &= ASSERT_TRUE(false, std::string("Wrong exception type: ") + e.what());
    }

    // Test same errors for decryption
    try {
        cipher.decryption(invalid_input, output);
        success &= ASSERT_TRUE(false, "Decryption should throw exception for non-valid size");
    } catch (const std::invalid_argument& e) {
        std::string error_msg = e.what();
        success &= ASSERT_TRUE(error_msg.find("must be at least one block size") != std::string::npos,
                    "Should mention block size condition in error message");
    } catch (const std::exception& e) {
        success &= ASSERT_TRUE(false, std::string("Wrong exception type: ") + e.what());
    }
    PRINT_RESULTS();
    return success;
}

bool test_exception_safety(AESKEY_LENBITS klb, AESCIPHER_OPTMODE mode) {
    TEST_SUITE("Exception Safety Tests");
    bool success = true;

    AESKEY key(klb);
    AESCIPHER cipher(key, mode);

    uint8_t input[NIST_TEXTSIZE];
    uint8_t output[NIST_TEXTSIZE];

    // Verify object is in valid state initially
    success &= ASSERT_TRUE(cipher.isKeyExpansionInitialized(), "Cipher should be properly initialized");

    try {
        // This should throw
        cipher.encrypt(nullptr, NIST_TEXTSIZE, output);
        success &= ASSERT_TRUE(false, "Should have thrown exception");
    } catch (const std::invalid_argument&) {
        // Object should still be usable after exception
        success &= ASSERT_TRUE(
            cipher.isKeyExpansionInitialized(),
            "Key expansion should still be initialized after exception"
        );
        try {
            cipher.encrypt(input, NIST_TEXTSIZE, output);
            success &= ASSERT_TRUE(true, "Cipher object remained usable after exception");
        } catch (const std::exception& e) {
            success &= ASSERT_TRUE(
                false,
                std::string("Cipher object corrupted after exception: ") + e.what()
            );
        }
    }
    PRINT_RESULTS();
    return success;
}

bool test_cbc_mode_iv_handling(AESKEY_LENBITS klb) {
    TEST_SUITE("CBC Mode IV Handling Tests");
    bool success = true;

    try {
        AESencryption::Key cbc_key(klb);
        AESCIPHER cbc_cipher(cbc_key, AESCIPHER_OPTMODE::CBC);

        std::vector<uint8_t> input(NIST_TEXTSIZE);
        std::vector<uint8_t> output(NIST_TEXTSIZE);

        // If IV is not properly set, it should throw an exception
        try {
            cbc_cipher.encryption(input, output);
            success &= ASSERT_TRUE(true, "CBC encryption succeeded (IV properly handled)");
        } catch (const std::exception& e) {
            std::string error_msg = e.what();
            if (error_msg.find("IV") != std::string::npos) {
                success &= ASSERT_TRUE(true, "CBC properly detected missing IV");
            } else {
                success &= ASSERT_TRUE(false, std::string("Unexpected CBC error: ") + e.what());
            }
        }

    } catch (const std::exception& e) {
        success &= ASSERT_TRUE(false, std::string("CBC IV test failed: ") + e.what());
    }
    PRINT_RESULTS();
    return success;
}

bool runTestsForKeylengthMode(AESKEY_LENBITS klb, AESCIPHER_OPTMODE mode){
    bool success = true;
    const char* keylenStr = CommonAESVectors::getKeylengthString(static_cast<COMAESVEC_KEYLEN>(klb));
    const char* optModeStr = NIST_GETMODESTRING(mode);
    std::cout << "\n*****************************************************************\n"
              << "\n========== AES key " << keylenStr << " bits, operation mode: " << optModeStr << " ============\n"
              << "\n*****************************************************************\n" << std::endl;

    success &= test_successful_operations(klb, mode);
    success &= test_empty_vector_exceptions(klb, mode);
    success &= test_invalid_size_exceptions(klb, mode);
    success &= test_exception_safety(klb, mode);
    success &= test_cbc_mode_iv_handling(klb);

    return success;
}
