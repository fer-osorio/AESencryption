#include"../include/test_framework.hpp"
#include"../../data-encryption/include/constants.h"
#include"../../data-encryption/include/AES.h"              // For key expansion
#include"../../data-encryption/include/operation_modes.h"
#include<cstring>
#include<vector>

#define PLAINTEXT_SIZE  32
#define CIPHERTEXT_SIZE 32

namespace TestVectors {
    // Standard test vectors from NIST SP 800-38A
    const uint8_t key_128[] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    const uint8_t iv[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    // Two blocks of plaintext
    const uint8_t plaintext_2blocks[] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
    };

    // Expected ECB result for 2 blocks
    const uint8_t expected_ecb_2blocks[] = {
        0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
        0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97,
        0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d,
        0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf
    };

    // Expected CBC result for 2 blocks
    const uint8_t expected_cbc_2blocks[] = {
        0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
        0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
        0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee,
        0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2
    };
}

void test_ecb_mode();
void test_cbc_mode();
void test_iv_independence();
void test_error_conditions();

int main() {
    std::cout << "=== Operation Modes Tests ===" << std::endl;

    test_ecb_mode();
    test_cbc_mode();
    test_iv_independence();
    test_error_conditions();

    std::cout << "\n=== Operation Modes Tests Complete ===" << std::endl;
    return 0;
}

void test_ecb_mode() {
    TEST_SUITE("ECB Mode Tests");

    uint8_t expanded_key[KEY_EXPANSION_LENGTH_128_BYTES]; // AES-128 expanded key
    uint8_t output[CIPHERTEXT_SIZE];        // 2 blocks
    uint8_t decrypted[PLAINTEXT_SIZE];

    // Prepare key expansion
    ASSERT_TRUE(
        KeyExpansionBuildWrite(TestVectors::key_128, static_cast<size_t>(Keylenbits128), expanded_key, false) == NoException,
        "Key expansion should succeed"
    );

    // Test ECB encryption
    ASSERT_TRUE(
        encryptECB(TestVectors::plaintext_2blocks, PLAINTEXT_SIZE, expanded_key, Keylenbits128, output) == NoException,
        "ECB encryption should succeed"
    );

    ASSERT_BYTES_EQUAL(
        TestVectors::expected_ecb_2blocks, output, CIPHERTEXT_SIZE,
        "ECB encryption should match test vector"
    );

    // Test ECB decryption
    ASSERT_TRUE(
        decryptECB(output, CIPHERTEXT_SIZE, expanded_key, Keylenbits128, decrypted) == NoException,
        "ECB decryption should succeed"
    );

    ASSERT_BYTES_EQUAL(
        TestVectors::plaintext_2blocks, decrypted, PLAINTEXT_SIZE,
        "ECB roundtrip should preserve plaintext"
    );

    PRINT_RESULTS();
}

void test_cbc_mode() {
    TEST_SUITE("CBC Mode Tests");

    uint8_t expanded_key[KEY_EXPANSION_LENGTH_128_BYTES];
    uint8_t output[CIPHERTEXT_SIZE];
    uint8_t decrypted[PLAINTEXT_SIZE];
    uint8_t iv_copy[BLOCK_SIZE];

    KeyExpansionBuildWrite(TestVectors::key_128, static_cast<size_t>(Keylenbits128), expanded_key, false);

    // Test CBC encryption
    memcpy(iv_copy, TestVectors::iv, BLOCK_SIZE);
    ASSERT_TRUE(
        encryptCBC(TestVectors::plaintext_2blocks, PLAINTEXT_SIZE, expanded_key, Keylenbits128, iv_copy, output) == NoException,
        "CBC encryption should succeed"
    );

    ASSERT_BYTES_EQUAL(
        TestVectors::expected_cbc_2blocks, output, CIPHERTEXT_SIZE,
        "CBC encryption should match test vector"
    );

    // Test CBC decryption
    ASSERT_TRUE(
        decryptCBC(output, CIPHERTEXT_SIZE, expanded_key, Keylenbits128, iv_copy, decrypted) == NoException,
        "CBC decryption should succeed"
    );

    ASSERT_BYTES_EQUAL(
        TestVectors::plaintext_2blocks, decrypted, PLAINTEXT_SIZE,
        "CBC roundtrip should preserve plaintext"
    );

    PRINT_RESULTS();
}

void test_iv_independence() {
    TEST_SUITE("IV Independence Tests");

    uint8_t expanded_key[KEY_EXPANSION_LENGTH_128_BYTES];
    uint8_t output1[CIPHERTEXT_SIZE], output2[CIPHERTEXT_SIZE];
    uint8_t iv1[BLOCK_SIZE], iv2[BLOCK_SIZE];

    KeyExpansionBuildWrite(TestVectors::key_128, static_cast<size_t>(Keylenbits128), expanded_key, false);

    // Set up two different IVs
    memcpy(iv1, TestVectors::iv, BLOCK_SIZE);
    memcpy(iv2, TestVectors::iv, BLOCK_SIZE);
    iv2[0] = 0xFF; // Make second IV different

    // Encrypt same plaintext with different IVs
    encryptCBC(TestVectors::plaintext_2blocks, PLAINTEXT_SIZE, expanded_key, Keylenbits128, iv1, output1);
    encryptCBC(TestVectors::plaintext_2blocks, PLAINTEXT_SIZE, expanded_key, Keylenbits128, iv2, output2);

    ASSERT_TRUE(
        memcmp(output1, output2, CIPHERTEXT_SIZE) != 0,
        "Different IVs should produce different ciphertext"
    );

    PRINT_RESULTS();
}

void test_error_conditions() {
    TEST_SUITE("Error Condition Tests");

    uint8_t expanded_key[KEY_EXPANSION_LENGTH_128_BYTES];
    uint8_t output[CIPHERTEXT_SIZE];
    uint8_t iv_copy[BLOCK_SIZE];

    KeyExpansionBuildWrite(TestVectors::key_128, static_cast<size_t>(Keylenbits128), expanded_key, false);
    memcpy(iv_copy, TestVectors::iv, BLOCK_SIZE);

    // Test null pointer handling
    ASSERT_TRUE(
        encryptECB(NULL, PLAINTEXT_SIZE, expanded_key, Keylenbits128, output) != NoException,
        "ECB should handle null input"
    );

    ASSERT_TRUE(
        encryptECB(TestVectors::plaintext_2blocks, PLAINTEXT_SIZE, expanded_key, Keylenbits128, NULL) != NoException,
        "ECB should handle null output"
    );

    ASSERT_TRUE(
        encryptCBC(TestVectors::plaintext_2blocks, PLAINTEXT_SIZE, expanded_key, Keylenbits128, NULL, output) == NullInitialVector,
        "CBC should handle null IV"
    );

    // Test zero length
    ASSERT_TRUE(
        encryptECB(TestVectors::plaintext_2blocks, 0, expanded_key, Keylenbits128, output) == ZeroLength,
        "ECB should handle zero length"
    );

    PRINT_RESULTS();
}
