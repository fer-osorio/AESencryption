#include"../include/test_framework.hpp"
#include"../../data-encryption/include/constants.h"
#include"../../data-encryption/include/AES.h"              // For key expansion
#include"../../data-encryption/include/operation_modes.h"
#include"../include/NIST_SP_800-38A_TestVectors.hpp"
#include<cstring>

bool test_ecb_mode(CommonAESVectors::KeylengthBits klb);
bool test_cbc_mode(CommonAESVectors::KeylengthBits klb);
bool test_iv_independence(CommonAESVectors::KeylengthBits klb);
bool test_error_conditions(CommonAESVectors::KeylengthBits klb);

NISTSP800_38A_Examples::ECB_ns::Example createECBencryptionExample(CommonAESVectors::KeylengthBits klb);
NISTSP800_38A_Examples::CBC_ns::Example createCBCencryptionExample(CommonAESVectors::KeylengthBits klb);

/**
 * @brief Runs the complete set of AES Operation Modes tests for a specific key length.
 *
 * This function prints a banner for the key length and then executes the ecb,
 * cbc, iv independence and error condition tests.
 *
 * @param kl The key length to test (e.g., keylen128).
 * @return true if all test pass, false otherwise.
 */
bool runTestsForKeylength(CommonAESVectors::KeylengthBits kl);

int main() {
    std::cout << "=== Operation Modes Tests ===" << std::endl;

    if(!runTestsForKeylength(CommonAESVectors::KeylengthBits::keylen128)){
        return 1; // Exit with error status.
    }
    if(!runTestsForKeylength(CommonAESVectors::KeylengthBits::keylen192)){
        return 1; // Exit with error status.
    }
    if(!runTestsForKeylength(CommonAESVectors::KeylengthBits::keylen256)){
        return 1; // Exit with error status.
    }

    std::cout << "\n=== Operation Modes Tests Complete ===" << std::endl;
    return 0;
}

bool test_ecb_mode(CommonAESVectors::KeylengthBits klb) {
    TEST_SUITE("ECB Mode Tests");

    bool successStatus = true;
    NISTSP800_38A_Examples::ECB_ns::Example ee = createECBencryptionExample(klb);
    const size_t expanded_key_len = getKeyExpansionLengthBytesfromKeylenBits(static_cast<KeylenBits_t>(klb));
    std::vector<uint8_t> expanded_key(expanded_key_len);                     // AES expanded key
    uint8_t output[NISTSP800_38A_Examples::TEXT_SIZE];                          // 2 blocks
    uint8_t decrypted[NISTSP800_38A_Examples::TEXT_SIZE];

    // Prepare key expansion
    successStatus = ASSERT_TRUE(
        KeyExpansionBuildWrite(ee.getKey(), static_cast<size_t>(ee.getKeylenBits()), expanded_key.data(), false) == NoException,
        "Key expansion should succeed"
    ) && successStatus;

    // Test ECB encryption
    successStatus = ASSERT_TRUE(
        encryptECB(ee.getInput(), NISTSP800_38A_Examples::TEXT_SIZE, expanded_key.data(), Keylenbits128, output) == NoException,
        "ECB encryption should succeed"
    ) && successStatus;

    successStatus = ASSERT_BYTES_EQUAL(
        ee.getExpectedOutput(), output, NISTSP800_38A_Examples::TEXT_SIZE,
        "ECB encryption should match test vector"
    ) && successStatus;

    // Test ECB decryption
    successStatus = ASSERT_TRUE(
        decryptECB(output, NISTSP800_38A_Examples::TEXT_SIZE, expanded_key.data(), Keylenbits128, decrypted) == NoException,
        "ECB decryption should succeed"
    ) && successStatus;

    successStatus = ASSERT_BYTES_EQUAL(
        NISTSP800_38A_Examples::commonPlaintext, decrypted, NISTSP800_38A_Examples::TEXT_SIZE,
        "ECB roundtrip should preserve plaintext"
    ) && successStatus;

    PRINT_RESULTS();

    return successStatus;
}

bool test_cbc_mode(CommonAESVectors::KeylengthBits klb) {
    TEST_SUITE("CBC Mode Tests");

    bool successStatus = true;
    NISTSP800_38A_Examples::CBC_ns::Example ee = createCBCencryptionExample(klb);
    const size_t expanded_key_len = getKeyExpansionLengthBytesfromKeylenBits(static_cast<KeylenBits_t>(klb));
    std::vector<uint8_t> expanded_key(expanded_key_len);
    uint8_t output[NISTSP800_38A_Examples::TEXT_SIZE];
    uint8_t decrypted[NISTSP800_38A_Examples::TEXT_SIZE];

    // Prepare key expansion
    successStatus = ASSERT_TRUE(
        KeyExpansionBuildWrite(ee.getKey(), static_cast<size_t>(ee.getKeylenBits()), expanded_key.data(), false) == NoException,
        "Key expansion should succeed"
    ) && successStatus;

    successStatus = ASSERT_TRUE(
        encryptCBC(NISTSP800_38A_Examples::commonPlaintext, NISTSP800_38A_Examples::TEXT_SIZE, expanded_key.data(), Keylenbits128, ee.getIV(), output) == NoException,
        "CBC encryption should succeed"
    ) && successStatus;

    successStatus = ASSERT_BYTES_EQUAL(
        ee.getExpectedOutput(), output, NISTSP800_38A_Examples::TEXT_SIZE,
        "CBC encryption should match test vector"
    ) && successStatus;

    // Test CBC decryption
    successStatus = ASSERT_TRUE(
        decryptCBC(output, NISTSP800_38A_Examples::TEXT_SIZE, expanded_key.data(), Keylenbits128, ee.getIV(), decrypted) == NoException,
        "CBC decryption should succeed"
    ) && successStatus;

    successStatus = ASSERT_BYTES_EQUAL(
        NISTSP800_38A_Examples::commonPlaintext, decrypted, NISTSP800_38A_Examples::TEXT_SIZE,
        "CBC roundtrip should preserve plaintext"
    ) && successStatus;

    PRINT_RESULTS();

    return successStatus;
}

bool test_iv_independence(CommonAESVectors::KeylengthBits klb) {
    TEST_SUITE("IV Independence Tests");

    bool successStatus = true;
    NISTSP800_38A_Examples::CBC_ns::Example ee = createCBCencryptionExample(klb);
    const size_t expanded_key_len = getKeyExpansionLengthBytesfromKeylenBits(static_cast<KeylenBits_t>(klb));
    std::vector<uint8_t> expanded_key(expanded_key_len);
    uint8_t output1[NISTSP800_38A_Examples::TEXT_SIZE], output2[NISTSP800_38A_Examples::TEXT_SIZE];
    uint8_t iv1[BLOCK_SIZE], iv2[BLOCK_SIZE];

    KeyExpansionBuildWrite(ee.getKey(), static_cast<size_t>(ee.getKeylenBits()), expanded_key.data(), false);

    // Set up two different IVs
    memcpy(iv1, ee.getIV(), BLOCK_SIZE);
    memcpy(iv2, ee.getIV(), BLOCK_SIZE);
    iv2[0] = 0xFF; // Make second IV different

    // Encrypt same plaintext with different IVs
    encryptCBC(NISTSP800_38A_Examples::commonPlaintext, NISTSP800_38A_Examples::TEXT_SIZE, expanded_key.data(), Keylenbits128, iv1, output1);
    encryptCBC(NISTSP800_38A_Examples::commonPlaintext, NISTSP800_38A_Examples::TEXT_SIZE, expanded_key.data(), Keylenbits128, iv2, output2);

    successStatus = ASSERT_TRUE(
        memcmp(output1, output2, NISTSP800_38A_Examples::TEXT_SIZE) != 0,
        "Different IVs should produce different ciphertext"
    );

    PRINT_RESULTS();

    return successStatus;
}

bool test_error_conditions(CommonAESVectors::KeylengthBits klb) {
    TEST_SUITE("Error Condition Tests");

    bool successStatus = true;
    NISTSP800_38A_Examples::ECB_ns::Example ee_ecb = createECBencryptionExample(klb);
    NISTSP800_38A_Examples::CBC_ns::Example ee_cbc = createCBCencryptionExample(klb);
    const size_t expanded_key_len = getKeyExpansionLengthBytesfromKeylenBits(static_cast<KeylenBits_t>(klb));
    std::vector<uint8_t> expanded_key(expanded_key_len);
    uint8_t output[NISTSP800_38A_Examples::TEXT_SIZE];
    uint8_t iv_copy[BLOCK_SIZE];

    KeyExpansionBuildWrite(ee_ecb.getKey(), static_cast<size_t>(ee_ecb.getKeylenBits()), expanded_key.data(), false);
    memcpy(iv_copy, ee_cbc.getIV(), BLOCK_SIZE);

    // Test null pointer handling
    successStatus = ASSERT_TRUE(
        encryptECB(NULL, NISTSP800_38A_Examples::TEXT_SIZE, expanded_key.data(), Keylenbits128, output) != NoException,
        "ECB should handle null input"
    ) && successStatus;

    successStatus = ASSERT_TRUE(
        encryptECB(NISTSP800_38A_Examples::commonPlaintext, NISTSP800_38A_Examples::TEXT_SIZE, expanded_key.data(), Keylenbits128, NULL) != NoException,
        "ECB should handle null output"
    ) && successStatus;

    successStatus = ASSERT_TRUE(
        encryptCBC(NULL, NISTSP800_38A_Examples::TEXT_SIZE, expanded_key.data(), Keylenbits128, ee_cbc.getIV(), output) == NullInitialVector,
        "CBC should handle null input"
    ) && successStatus;

    successStatus = ASSERT_TRUE(
        encryptCBC(NISTSP800_38A_Examples::commonPlaintext, NISTSP800_38A_Examples::TEXT_SIZE, expanded_key.data(), Keylenbits128, ee_cbc.getIV(), NULL) == NullInitialVector,
        "CBC should handle null input"
    ) && successStatus;

    successStatus = ASSERT_TRUE(
        encryptCBC(NISTSP800_38A_Examples::commonPlaintext, NISTSP800_38A_Examples::TEXT_SIZE, expanded_key.data(), Keylenbits128, NULL, output) == NullInitialVector,
        "CBC should handle null IV"
    ) && successStatus;

    // Test zero length
    successStatus = ASSERT_TRUE(
        encryptECB(NISTSP800_38A_Examples::commonPlaintext, 0, expanded_key.data(), Keylenbits128, output) == ZeroLength,
        "ECB should handle zero length"
    ) && successStatus;

    successStatus = ASSERT_TRUE(
        encryptCBC(NISTSP800_38A_Examples::commonPlaintext, 0, expanded_key.data(), Keylenbits128, ee_cbc.getIV(), output) == ZeroLength,
        "CBC should handle zero length"
    ) && successStatus;

    PRINT_RESULTS();

    return successStatus;
}

NISTSP800_38A_Examples::ECB_ns::Example createECBencryptionExample(CommonAESVectors::KeylengthBits klb){
    return CommonAESVectors::ExampleFactory<NISTSP800_38A_Examples::ECB_ns::Example>::createEncryptionExample(klb);
}

NISTSP800_38A_Examples::CBC_ns::Example createCBCencryptionExample(CommonAESVectors::KeylengthBits klb){
    return CommonAESVectors::ExampleFactory<NISTSP800_38A_Examples::CBC_ns::Example>::createEncryptionExample(klb);
}

bool runTestsForKeylength(CommonAESVectors::KeylengthBits klb) {
    const char* keylenStr = CommonAESVectors::getKeylengthString(klb);
    bool successStatus = true;
    std::cout << "\n*****************************************************************\n"
              << "\n======================= AES key " << keylenStr << " bits ========================\n"
              << "\n*****************************************************************\n" << std::endl;

    successStatus = test_ecb_mode(klb) && successStatus;
    successStatus = test_cbc_mode(klb) && successStatus;
    successStatus = test_iv_independence(klb) && successStatus;
    successStatus = test_error_conditions(klb) && successStatus;

    std::cout << std::endl;
    return successStatus;
}
