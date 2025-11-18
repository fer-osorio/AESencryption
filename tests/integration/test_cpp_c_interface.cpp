#include "../include/test_framework.hpp"
#include "../../data-encryption/include/constants.h"
#include "../../data-encryption/include/AES.h"
#include "../../data-encryption/include/operation_modes.h"
#include "../../include/cipher.hpp"
#include "../../include/key.hpp"
#include "../include/NIST_SP_800-38A_TestVectors.hpp"
#include <cstring>

#define AESKEY AESencryption::Key
#define AESENC_KEYLEN AESencryption::Key::LengthBits
#define AESCIPHER AESencryption::Cipher
#define AESENC_OPTMODE AESencryption::Cipher::OperationMode::Identifier

bool test_specific_exception_code_mapping(AESENC_KEYLEN klb, AESENC_OPTMODE mode);
bool test_key_expansion_initialization(AESENC_KEYLEN klb, AESENC_OPTMODE mode);
bool test_consistency_with_c_implementation(AESENC_KEYLEN klb, AESENC_OPTMODE mode);

/**
 * @brief Runs the complete set of tests for a specific key length and operation mode.
 *
 * This function prints a banner for the key length and then executes all tests.
 *
 * @param kl The key length to test.
 * @param mode The operation mode to test
 * @return true if all tests passed, false otherwise.
 */
bool runTestsForKeylengthMode(AESENC_KEYLEN klb, AESENC_OPTMODE mode);

int main() {
    std::cout << "===================== C/C++ Interface Integration Tests =====================" << std::endl;
    std::vector<AESENC_KEYLEN> keylengths = { AESENC_KEYLEN::_128, AESENC_KEYLEN::_192, AESENC_KEYLEN::_256 };
    std::vector<AESENC_OPTMODE> optModes = { AESENC_OPTMODE::ECB, AESENC_OPTMODE::CBC };
    bool allTestsSucceed = true;

    for(AESENC_KEYLEN klb: keylengths){
        for(AESENC_OPTMODE mode: optModes){
            allTestsSucceed &= runTestsForKeylengthMode(klb,mode);
        }
    }

    if(allTestsSucceed) {
        std::cout << "\n===================== All C/C++ Interface Integration Tests Succeed =====================" << std::endl;
        return 0;
    } else {
        std::cout << "\n===================== Some C/C++ Interface Integration Tests Failed =====================" << std::endl;
        return 1;
    }
}

bool test_specific_exception_code_mapping(AESENC_KEYLEN klb, AESENC_OPTMODE mode) {
    TEST_SUITE("Specific Exception Code Mapping Tests");
    bool success = true;
    // Test direct C function calls and their error codes
    std::vector<uint8_t> dummy_key(static_cast<size_t>(klb)/8, 0);
    size_t c_klb = static_cast<size_t>(klb);
    ptrKeyExpansion_t c_ke = KeyExpansionMemoryAllocationBuild(dummy_key.data(), c_klb, false);
    size_t ke_lenbytes = getKeyExpansionLengthBytesfromKeylenBits(static_cast<enum KeylenBits_t>(c_klb));
    std::vector<uint8_t> c_key_expansion(ke_lenbytes);
    KeyExpansionWriteBytes(c_ke, c_key_expansion.data());

    if (c_ke != nullptr) {
        const uint8_t* key_expansion_ptr = c_key_expansion.data();
        uint8_t input[BLOCK_SIZE];
        uint8_t output[BLOCK_SIZE];

        // Test NullInput error code
        enum ExceptionCode result = encryptECB(nullptr, BLOCK_SIZE, key_expansion_ptr, c_klb, output);
        success &= ASSERT_TRUE(result == NullInput, "C function should return NullInput for null input");

        // Test NullOutput error code
        result = encryptECB(input, BLOCK_SIZE, key_expansion_ptr, c_klb, nullptr);
        success &= ASSERT_TRUE(result == NullOutput, "C function should return NullOutput for null output");

        // Test InvalidInputSize error code
        result = encryptECB(input, 15, key_expansion_ptr, 128, output);
        success &= ASSERT_TRUE(result == InvalidInputSize, "C function should return InvalidInputSize for non-valid size");

        // Test ZeroLength error code
        result = encryptECB(input, 0, key_expansion_ptr, 128, output);
        success &= ASSERT_TRUE(result == ZeroLength, "C function should return ZeroLength for zero size");

        // Test NullKeyExpansion error code
        result = encryptECB(input, BLOCK_SIZE, nullptr, 128, output);
        success &= ASSERT_TRUE(result == NullSource, "C function should return NullSource for null key expansion argument");

        KeyExpansionDelete(&c_ke);
    } else{
        std::cerr << "No test runned. Something went wrong in key creation.";
    }
    PRINT_RESULTS();
    return success;
}

bool test_key_expansion_initialization(AESENC_KEYLEN klb, AESENC_OPTMODE mode) {
    TEST_SUITE("Key Expansion Initialization Tests");
    bool success = true;
    // Test that key expansion is properly initialized
    size_t keylen = static_cast<size_t>(klb);
    size_t ke_lenbytes = getKeyExpansionLengthBytesfromKeylenBits(static_cast<enum KeylenBits_t>(keylen));
    std::vector<uint8_t> dumm(keylen/8, 1);
    AESKEY key(dumm, klb);
    AESencryption::Cipher cipher(key, AESCIPHER::OperationMode(mode));

    success &= ASSERT_TRUE(
        cipher.isKeyExpansionInitialized(),
        "Key expansion should be initialized after construction"
    );

    const uint8_t* key_expansion_ptr = cipher.getKeyExpansionForTesting();
    success &= ASSERT_NOT_NULL(
        key_expansion_ptr,
        "Key expansion pointer should not be null"
    );

    // Compare with direct C implementation
    ptrKeyExpansion_t c_ke = KeyExpansionMemoryAllocationBuild(dumm.data(), keylen, false);
    if (c_ke != nullptr) {
        std::vector<uint8_t> c_key_expansion(ke_lenbytes);
        KeyExpansionWriteBytes(c_ke, c_key_expansion.data());

        // Compare bytes to verify consistency
        success &= ASSERT_BYTES_EQUAL(
            c_key_expansion.data(), key_expansion_ptr, BLOCK_SIZE,
            "c key expansion and c++ key expansion should match"
        );

        KeyExpansionDelete(&c_ke);
    }
    PRINT_RESULTS();
    return success;
}

bool test_consistency_with_c_implementation(AESENC_KEYLEN klb, AESENC_OPTMODE mode) {
    NIST_EXAMPLEBASE_UPTR example = NIST_CREATEEXAMPLE(klb,mode);
    if (!example) {
        // Handle the error if the mode is unsupported
        std::cerr << "Error: Unsupported operation mode." << std::endl;
        return false;
    }
    TEST_SUITE("C vs C++ Consistency Tests");
    bool success = true;
    try {
        // Direct C implementation
        size_t sz_klb = static_cast<size_t>(klb);
        ptrKeyExpansion_t c_ke = KeyExpansionMemoryAllocationBuild(example->getKey(), sz_klb, false);
        success &= ASSERT_NOT_NULL(
            c_ke,
            "C key expansion creation should succeed"
        );

        std::vector<uint8_t> key_expansion_bytes(getKeyExpansionLengthBytesfromKeylenBits(static_cast<KeylenBits_t>(klb)));
        KeyExpansionWriteBytes(c_ke, key_expansion_bytes.data());
        uint8_t c_output[NIST_TEXTSIZE];

        // C++ wrapper implementation
        AESKEY cpp_key(example->getKeyAsVector(), klb);
        AESencryption::Cipher cpp_cipher(cpp_key, AESCIPHER::OperationMode(mode));

        enum ExceptionCode c_result = [&]() -> enum ExceptionCode{
            switch(mode){
                case AESENC_OPTMODE::ECB:
                    return encryptECB(example->getInput(), NIST_TEXTSIZE, key_expansion_bytes.data(), sz_klb, c_output);
                    break;
                case AESENC_OPTMODE::CBC:
                    return encryptCBC(example->getInput(), NIST_TEXTSIZE, key_expansion_bytes.data(), sz_klb, cpp_cipher.getInitialVectorForTesting(), c_output);
                    break;
                break;
                default:
                    return UnknownOperation;
                    break;
            }
        }();
        success &= ASSERT_TRUE(
            c_result == NoException,
            "C encryption should succeed with NoException"
        );

        uint8_t cpp_output[NIST_TEXTSIZE];
        cpp_cipher.encrypt(example->getInput(), NIST_TEXTSIZE, cpp_output);

        success &= ASSERT_BYTES_EQUAL(
            c_output, cpp_output, NIST_TEXTSIZE,
            "C++ wrapper should produce same result as direct C"
        );

        // Test decryption consistency
        uint8_t c_decrypted[NIST_TEXTSIZE];
        uint8_t cpp_decrypted[NIST_TEXTSIZE];

        c_result = [&]() -> enum ExceptionCode{
            switch(mode){
                case AESENC_OPTMODE::ECB:
                    return decryptECB(c_output, NIST_TEXTSIZE, key_expansion_bytes.data(), sz_klb, c_decrypted);
                    break;
                case AESENC_OPTMODE::CBC:
                    return decryptCBC(c_output, NIST_TEXTSIZE, key_expansion_bytes.data(), sz_klb, cpp_cipher.getInitialVectorForTesting(), c_decrypted);
                    break;
                break;
                default:
                    return UnknownOperation;
                    break;
            }
        }();
        success &= ASSERT_TRUE(c_result == NoException, "C decryption should succeed");

        cpp_cipher.decrypt(cpp_output, NIST_TEXTSIZE, cpp_decrypted);

        success &= ASSERT_BYTES_EQUAL(c_decrypted, cpp_decrypted, NIST_TEXTSIZE,
                           "C++ and C decryption should produce same result");

        success &= ASSERT_BYTES_EQUAL(example->getInput(), cpp_decrypted, NIST_TEXTSIZE,
                           "Both implementations should correctly decrypt data");

        KeyExpansionDelete(&c_ke);

    } catch (const std::exception& e) {
        success &= ASSERT_TRUE(false, std::string("Consistency test failed with exception: ") + e.what());
    }
    PRINT_RESULTS();
    return success;
}

bool runTestsForKeylengthMode(AESENC_KEYLEN klb, AESENC_OPTMODE mode){
    bool success = true;
    const char* keylenStr = COMAESVEC_GETKEYLENSTR(klb);
    const char* optModeStr = NIST_GETMODESTRING(mode);
    std::cout << "\n*****************************************************************\n"
              << "\n========== AES key " << keylenStr << " bits, operation mode: " << optModeStr << " ============\n"
              << "\n*****************************************************************\n" << std::endl;

    success &= test_specific_exception_code_mapping(klb, mode);
    success &= test_key_expansion_initialization(klb, mode);
    success &= test_consistency_with_c_implementation(klb, mode);

    return success;
}
