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
#define CREATE_EXAMPLE(klb,mode) NISTSP800_38A_Examples::createExample(static_cast<COMMAESVECT_KEYLEN>(klb), static_cast<COMMAESVECT_OPTMODE>(mode))

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

void test_empty_vector_exceptions(AESENC_KEYLEN klb, AESENC_OPTMODE mode) {
    TEST_SUITE("Empty Vector Exception Tests");

    AESKEY key(klb);
    AESencryption::Cipher cipher(key, mode);

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

void test_key_expansion_initialization(AESENC_KEYLEN klb, AESENC_OPTMODE mode) {
    TEST_SUITE("Key Expansion Initialization Tests");

    // Test that key expansion is properly initialized
    size_t keylen = static_cast<size_t>(klb);
    size_t ke_lenbytes = getKeyExpansionLengthBytesfromKeylenBits(static_cast<enum KeylenBits_t>(keylen));
    std::vector<uint8_t> dumm(keylen/8, 1);
    AESKEY key(dumm, klb);
    AESencryption::Cipher cipher(key, mode);

    ASSERT_TRUE(
        cipher.isKeyExpansionInitialized(),
        "Key expansion should be initialized after construction"
    );

    const uint8_t* key_expansion_ptr = cipher.getKeyExpansionForTesting();
    ASSERT_NOT_NULL(
        key_expansion_ptr,
        "Key expansion pointer should not be null"
    );

    // Compare with direct C implementation
    ptrKeyExpansion_t c_ke = KeyExpansionMemoryAllocationBuild(dumm.data(), keylen, false);
    if (c_ke != nullptr) {
        std::vector<uint8_t> c_key_expansion(ke_lenbytes);
        KeyExpansionWriteBytes(c_ke, c_key_expansion.data());

        // Compare bytes to verify consistency
        ASSERT_BYTES_EQUAL(
            c_key_expansion.data(), key_expansion_ptr, BLOCK_SIZE,
            "c key expansion and c++ key expansion should match"
        );

        KeyExpansionDelete(&c_ke);
    }

    PRINT_RESULTS();
}

void test_exception_safety(AESENC_KEYLEN klb, AESENC_OPTMODE mode) {
    TEST_SUITE("Exception Safety Tests");

    AESKEY key(klb);
    AESencryption::Cipher cipher(key, mode);

    uint8_t input[BLOCK_SIZE];
    uint8_t output[BLOCK_SIZE];

    // Verify object is in valid state initially
    ASSERT_TRUE(cipher.isKeyExpansionInitialized(), "Cipher should be properly initialized");

    try {
        // This should throw
        cipher.encrypt(nullptr, BLOCK_SIZE, output);
        ASSERT_TRUE(false, "Should have thrown exception");
    } catch (const std::invalid_argument&) {
        // Object should still be usable after exception
        ASSERT_TRUE(
            cipher.isKeyExpansionInitialized(),
            "Key expansion should still be initialized after exception"
        );
        try {
            cipher.encrypt(input, BLOCK_SIZE, output);
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

void test_consistency_with_c_implementation(AESENC_KEYLEN klb, AESENC_OPTMODE mode) {
    std::unique_ptr<EXAMPLE_BASE> example = CREATE_EXAMPLE(klb,mode);
    if (!example) {
        // Handle the error if the mode is unsupported
        std::cerr << "Error: Unsupported operation mode." << std::endl;
        return;
    }
    TEST_SUITE("C vs C++ Consistency Tests");

    try {
        // Direct C implementation
        size_t sz_klb = static_cast<size_t>(klb);
        ptrKeyExpansion_t c_ke = KeyExpansionMemoryAllocationBuild(example->getKey(), sz_klb, false);
        ASSERT_NOT_NULL(
            c_ke,
            "C key expansion creation should succeed"
        );

        std::vector<uint8_t> key_expansion_bytes(sz_klb/8);
        KeyExpansionWriteBytes(c_ke, key_expansion_bytes.data());
        uint8_t c_output[TEXT_SIZE];

        // C++ wrapper implementation
        AESKEY cpp_key(example->getKeyAsVector(), klb);
        AESencryption::Cipher cpp_cipher(cpp_key, mode);

        enum ExceptionCode c_result = [&]() -> enum ExceptionCode{
            switch(mode){
                case AESENC_OPTMODE::ECB:
                    return encryptECB(example->getInput(), TEXT_SIZE, key_expansion_bytes.data(), sz_klb, c_output);
                    break;
                case AESENC_OPTMODE::CBC:
                    return encryptCBC(example->getInput(), TEXT_SIZE, key_expansion_bytes.data(), sz_klb, cpp_cipher.getInitialVectorForTesting(), c_output);
                    break;
                break;
                default:
                    return UnknownOperation;
                    break;
            }
        }();
        ASSERT_TRUE(
            c_result == NoException,
            "C encryption should succeed with NoException"
        );

        uint8_t cpp_output[TEXT_SIZE];
        cpp_cipher.encrypt(example->getInput(), TEXT_SIZE, cpp_output);

        ASSERT_BYTES_EQUAL(
            c_output, cpp_output, TEXT_SIZE,
            "C++ wrapper should produce same result as direct C"
        );

        // Test decryption consistency
        uint8_t c_decrypted[TEXT_SIZE];
        uint8_t cpp_decrypted[TEXT_SIZE];

        c_result = [&]() -> enum ExceptionCode{
            switch(mode){
                case AESENC_OPTMODE::ECB:
                    return encryptECB(c_output, TEXT_SIZE, key_expansion_bytes.data(), sz_klb, c_decrypted);
                    break;
                case AESENC_OPTMODE::CBC:
                    return encryptCBC(c_output, TEXT_SIZE, key_expansion_bytes.data(), sz_klb, cpp_cipher.getInitialVectorForTesting(), c_decrypted);
                    break;
                break;
                default:
                    return UnknownOperation;
                    break;
            }
        }();
        ASSERT_TRUE(c_result == NoException, "C decryption should succeed");

        cpp_cipher.decrypt(cpp_output, TEXT_SIZE, cpp_decrypted);

        ASSERT_BYTES_EQUAL(c_decrypted, cpp_decrypted, TEXT_SIZE,
                           "C++ and C decryption should produce same result");

        ASSERT_BYTES_EQUAL(example->getInput(), cpp_decrypted, TEXT_SIZE,
                           "Both implementations should correctly decrypt data");

        KeyExpansionDelete(&c_ke);

    } catch (const std::exception& e) {
        ASSERT_TRUE(false, std::string("Consistency test failed with exception: ") + e.what());
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

int main() {
    std::cout << "=== C/C++ Interface Integration Tests with Specific Exception Handling ===" << std::endl;

    test_successful_operations();
    test_empty_vector_exceptions();
    test_invalid_size_exceptions();
    test_specific_exception_code_mapping();
    test_key_expansion_initialization();
    test_exception_safety();
    test_consistency_with_c_implementation();
    test_cbc_mode_iv_handling();

    std::cout << "\n=== Interface Integration Tests Complete ===" << std::endl;
    return 0;
}
