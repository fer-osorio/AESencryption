// Tests for data-encryption/AES.h

#include "../include/test_framework.hpp"
#include "../../data-encryption/include/AES.h"
#include "../../include/constants.hpp"
#include <cstring>

// Test vectors from NIST SP 800-38A
namespace TestVectors {
    // AES-128 test vector
    const uint8_t key_128[] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    const uint8_t plaintext[] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
    };

    const uint8_t expected_ciphertext_128[] = {
        0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
        0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97
    };
}

// Test functions
void test_aes_key_expansion() {
    TEST_SUITE("AES Key Expansion Tests");
    uint8_t KeyExpansionFirstRound[16];
    KeyExpansion_ptr ke_p = KeyExpansionMemoryAllocationBuild(TestVectors::key_128, Nk128, false);

    // Test key expansion for 128-bit key
    ASSERT_TRUE(ke_p == NULL, "AES-128 key expansion should succeed");

    // Verify first round key (should be original key)
    ASSERT_BYTES_EQUAL(TestVectors::key_128, KeyExpansionReturnBytePointerToData(ke_p), 16, "First round key should match original key");

    KeyExpansionDelete(&ke_p);
    ke_p = KeyExpansionMemoryAllocationBuild(TestVectors::key_128, 32, false);
    // Test invalid key length
    ASSERT_TRUE(ke_p != NULL, "Invalid key length should return null pointer");

    PRINT_RESULTS();
}

void test_aes_encrypt_block() {
    TEST_SUITE("AES Block Encryption Tests");

    uint8_t expanded_key[AESconstants::keyExpansionLength128 * 4];
    uint8_t output[AESconstants::BLOCK_SIZE];

    // Prepare key expansion
    aes_key_expansion(TestVectors::key_128, 128, expanded_key);

    // Test single block encryption
    ASSERT_TRUE(aes_encrypt_block(TestVectors::plaintext, output, expanded_key, 10) == 0,
                "AES block encryption should succeed");

    ASSERT_BYTES_EQUAL(TestVectors::expected_ciphertext_128, output,
                       AESconstants::BLOCK_SIZE, "Encrypted block should match test vector");

    // Test null pointer handling
    ASSERT_TRUE(aes_encrypt_block(nullptr, output, expanded_key, 10) != 0,
                "Null input should return error");

    PRINT_RESULTS();
}

void test_aes_decrypt_block() {
    TEST_SUITE("AES Block Decryption Tests");

    uint8_t expanded_key[AESconstants::keyExpansionLength128 * 4];
    uint8_t decrypted[AESconstants::BLOCK_SIZE];

    // Prepare key expansion
    aes_key_expansion(TestVectors::key_128, 128, expanded_key);

    // Test decryption
    ASSERT_TRUE(aes_decrypt_block(TestVectors::expected_ciphertext_128, decrypted,
                                  expanded_key, 10) == 0,
                "AES block decryption should succeed");

    ASSERT_BYTES_EQUAL(TestVectors::plaintext, decrypted, AESconstants::BLOCK_SIZE,
                       "Decrypted block should match original plaintext");

    PRINT_RESULTS();
}

void test_encryption_decryption_roundtrip() {
    TEST_SUITE("AES Roundtrip Tests");

    uint8_t expanded_key[AESconstants::keyExpansionLength128 * 4];
    uint8_t encrypted[AESconstants::BLOCK_SIZE];
    uint8_t decrypted[AESconstants::BLOCK_SIZE];

    // Prepare key expansion
    aes_key_expansion(TestVectors::key_128, 128, expanded_key);

    // Encrypt then decrypt
    aes_encrypt_block(TestVectors::plaintext, encrypted, expanded_key, 10);
    aes_decrypt_block(encrypted, decrypted, expanded_key, 10);

    ASSERT_BYTES_EQUAL(TestVectors::plaintext, decrypted, AESconstants::BLOCK_SIZE,
                       "Roundtrip encryption/decryption should preserve data");

    PRINT_RESULTS();
}

int main() {
    std::cout << "=== AES Core Implementation Tests ===" << std::endl;

    test_aes_key_expansion();
    test_aes_encrypt_block();
    test_aes_decrypt_block();
    test_encryption_decryption_roundtrip();

    std::cout << "\n=== All AES Core Tests Complete ===" << std::endl;
    return 0;
}
