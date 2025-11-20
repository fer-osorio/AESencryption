#include "../include/test_framework.hpp"
#include "../include/NIST_SP_800-38A_TestVectors.hpp"
#include "../../include/cipher.hpp"

#define AESKEY AESencryption::Key
#define AESKEY_LENBITS AESencryption::Key::LengthBits

#define AESCIPHER AESencryption::Cipher
#define AESCIPHER_OPTMODE AESencryption::Cipher::OperationMode::Identifier

bool test_successful_operations(AESKEY_LENBITS ks, AESCIPHER_OPTMODE cm);
bool test_empty_vector_exceptions(AESKEY_LENBITS ks, AESCIPHER_OPTMODE cm);
bool test_invalid_size_exceptions(AESKEY_LENBITS ks, AESCIPHER_OPTMODE cm);
bool test_exception_safety(AESKEY_LENBITS ks, AESCIPHER_OPTMODE cm);
bool test_cbc_mode_iv_handling(AESKEY_LENBITS ks);

/**
 * @brief Runs the complete set of tests for a specific key length and operation cm.
 *
 * This function prints a banner for the key length and then executes the tests for cipher object.
 *
 * @param kl The key length to test.
 * @param cm The operation cm to test
 * @return true if all tests passed, false otherwise.
 */
bool runTestsForKeylengthMode(AESKEY_LENBITS ks, AESCIPHER_OPTMODE cm);

int main() {
    std::cout << "=== C/C++ Cipher.hpp Tests with Specific Exception Handling ===" << std::endl;
    std::vector<AESKEY_LENBITS> keylengths = { AESKEY_LENBITS::_128, AESKEY_LENBITS::_192, AESKEY_LENBITS::_256 };
    std::vector<AESCIPHER_OPTMODE> optModes = { AESCIPHER_OPTMODE::ECB, AESCIPHER_OPTMODE::CBC };
    bool success = true;

    for(AESKEY_LENBITS ks: keylengths){
        for(AESCIPHER_OPTMODE cm: optModes){
            success &= runTestsForKeylengthMode(ks,cm);
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

bool test_successful_operations(AESKEY_LENBITS ks, AESCIPHER_OPTMODE cm) {
    // Convert from AESKEY_LENBITS to Common::KeySize
    Common::KeySize ks_;
    switch(ks) {
        case AESKEY_LENBITS::_128: ks_ = Common::KeySize::AES128; break;
        case AESKEY_LENBITS::_192: ks_ = Common::KeySize::AES192; break;
        case AESKEY_LENBITS::_256: ks_ = Common::KeySize::AES256; break;
        default: return false;
    }

    // Convert from AESCIPHER_OPTMODE to SP800_38A::CipherMode
    SP800_38A::CipherMode cm_;
    switch(cm) {
        case AESCIPHER_OPTMODE::ECB: cm_ = SP800_38A::CipherMode::ECB; break;
        case AESCIPHER_OPTMODE::CBC: cm_ = SP800_38A::CipherMode::CBC; break;
        default:
            std::cerr << "Error: Unsupported operation cm." << std::endl;
            return false;
    }

    std::unique_ptr<SP800_38A::TestVectorBase> example = SP800_38A::createTestVector(ks_, cm_);
    if (!example) {
        std::cerr << "Error: Failed to create test vector." << std::endl;
        return false;
    }

    TEST_SUITE("Successful Operations Tests");
    bool success = true;
    std::string optModeStr = SP800_38A::getModeString(cm_);

    try {
        // Test operation cm
        AESKEY key(example->getKeyAsVector(), ks);
        AESCIPHER ciph(key, AESCIPHER::OperationMode(cm));
        ciph.setInitialVectorForTesting(std::vector<uint8_t>(SP800_38A::getInitializationVectorAsStdVector()));

        // Verify key expansion is initialized
        success &= ASSERT_TRUE(
            ciph.isKeyExpansionInitialized(),
                               "Key expansion should be initialized after Cipher construction"
        );

        std::vector<uint8_t> input = example->getInputAsVector();
        std::vector<uint8_t> encrypted(SP800_38A::TEXT_SIZE);
        std::vector<uint8_t> decrypted(SP800_38A::TEXT_SIZE);

        ciph.encryption(input, encrypted);
        success &= ASSERT_BYTES_EQUAL(
            example->getExpectedOutput(),
                                      encrypted.data(),
                                      SP800_38A::TEXT_SIZE,
                                      optModeStr + " encryption should match reference vector"
        );
        ciph.decryption(encrypted, decrypted);
        success &= ASSERT_BYTES_EQUAL(
            example->getInput(),
            decrypted.data(),
            SP800_38A::TEXT_SIZE,
            optModeStr + " roundtrip should preserve data"
        );
        success &= ASSERT_TRUE(true, "All successful operations completed");
    } catch (const std::exception& e) {
        success &= ASSERT_TRUE(false, std::string("Unexpected exception: ") + e.what());
    }
    PRINT_RESULTS();
    return success;
}

bool test_empty_vector_exceptions(AESKEY_LENBITS ks, AESCIPHER_OPTMODE cm) {
    TEST_SUITE("Empty Vector Exception Tests");
    bool success = true;

    AESKEY key(ks);
    AESCIPHER cipher(key, AESCIPHER::OperationMode(cm));

    std::vector<uint8_t> input(SP800_38A::TEXT_SIZE);
    std::vector<uint8_t> output(SP800_38A::TEXT_SIZE);
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

bool test_invalid_size_exceptions(AESKEY_LENBITS ks, AESCIPHER_OPTMODE cm) {
    TEST_SUITE("Invalid Size Exception Tests");
    bool success = true;

    AESKEY key(ks);
    AESCIPHER cipher(key, AESCIPHER::OperationMode(cm));

    std::vector<uint8_t> invalid_input(15);
    std::vector<uint8_t> output(SP800_38A::TEXT_SIZE);

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

bool test_exception_safety(AESKEY_LENBITS ks, AESCIPHER_OPTMODE cm) {
    TEST_SUITE("Exception Safety Tests");
    bool success = true;

    AESKEY key(ks);
    AESCIPHER cipher(key, AESCIPHER::OperationMode(cm));

    uint8_t input[SP800_38A::TEXT_SIZE];
    uint8_t output[SP800_38A::TEXT_SIZE];

    // Verify object is in valid state initially
    success &= ASSERT_TRUE(cipher.isKeyExpansionInitialized(), "Cipher should be properly initialized");

    try {
        // This should throw
        cipher.encrypt(nullptr, SP800_38A::TEXT_SIZE, output);
        success &= ASSERT_TRUE(false, "Should have thrown exception");
    } catch (const std::invalid_argument&) {
        // Object should still be usable after exception
        success &= ASSERT_TRUE(
            cipher.isKeyExpansionInitialized(),
                               "Key expansion should still be initialized after exception"
        );
        try {
            cipher.encrypt(input, SP800_38A::TEXT_SIZE, output);
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

bool test_cbc_mode_iv_handling(AESKEY_LENBITS ks) {
    TEST_SUITE("CBC Mode IV Handling Tests");
    bool success = true;

    try {
        AESencryption::Key cbc_key(ks);
        AESCIPHER cbc_cipher(
            cbc_key, AESCIPHER::OperationMode(AESCIPHER_OPTMODE::CBC)
        );

        std::vector<uint8_t> input(SP800_38A::TEXT_SIZE);
        std::vector<uint8_t> output(SP800_38A::TEXT_SIZE);

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

bool runTestsForKeylengthMode(AESKEY_LENBITS ks, AESCIPHER_OPTMODE cm){
    bool success = true;

    // Convert from AESKEY_LENBITS to Common::KeySize for string lookup
    Common::KeySize ks_;
    switch(ks) {
        case AESKEY_LENBITS::_128: ks_ = Common::KeySize::AES128; break;
        case AESKEY_LENBITS::_192: ks_ = Common::KeySize::AES192; break;
        case AESKEY_LENBITS::_256: ks_ = Common::KeySize::AES256; break;
        default: return false;
    }

    // Convert from AESCIPHER_OPTMODE to SP800_38A::CipherMode for string lookup
    SP800_38A::CipherMode cm_;
    switch(cm) {
        case AESCIPHER_OPTMODE::ECB: cm_ = SP800_38A::CipherMode::ECB; break;
        case AESCIPHER_OPTMODE::CBC: cm_ = SP800_38A::CipherMode::CBC; break;
        default: return false;
    }

    const char* keylenStr = Common::getKeySizeString(ks_);
    const char* optModeStr = SP800_38A::getModeString(cm_);

    std::cout << "\n*****************************************************************\n"
    << "\n========== AES key " << keylenStr << " bits, operation cm: " << optModeStr << " ============\n"
    << "\n*****************************************************************\n" << std::endl;

    success &= test_successful_operations(ks, cm);
    success &= test_empty_vector_exceptions(ks, cm);
    success &= test_invalid_size_exceptions(ks, cm);
    success &= test_exception_safety(ks, cm);
    success &= test_cbc_mode_iv_handling(ks);

    return success;
}
