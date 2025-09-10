// Tests for data-encryption/AES.h

#include"../include/test_framework.hpp"
#include"../../data-encryption/include/AES.h"
#include"../../data-encryption/include/constants.h"
#include<cstring>

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

bool test_KeyExpansionMemoryAllocationBuild();
bool test_encryptBlock();
bool test_decryptBlock();
bool test_encryptionDecryptionRoundtrip();

int main() {
    std::cout << "=== AES Core Implementation Tests ===" << std::endl;

    if(test_KeyExpansionMemoryAllocationBuild() == false) {
        std::cout << "\n=== Fail to create a valid Key Expansion object. Stop. ===" << std::endl;
        return 0;
    }
    test_encryptBlock();
    test_decryptBlock();
    test_encryptionDecryptionRoundtrip();

    std::cout << "\n=== All AES Core Tests Complete ===" << std::endl;
    return 0;
}

// Test functions
bool test_KeyExpansionMemoryAllocationBuild() {
    TEST_SUITE("AES Key Expansion Tests");
    KeyExpansion_ptr ke_p = KeyExpansionMemoryAllocationBuild(TestVectors::key_128, Nk128, true);
    bool success = true;

    // Test key expansion for 128-bit key
    // Wrapped in a if statement to guard agains access to null pointer.
    if(!ASSERT_NOT_NULL(ke_p, "AES-128 key expansion should succeed")) return false;

    // Verify first round key (should be original key)
    success = success && ASSERT_BYTES_EQUAL(TestVectors::key_128, KeyExpansionReturnBytePointerToData(ke_p), 16, "First round key should match original key");

    KeyExpansionDelete(&ke_p);

    // Try to build new key with invalid key length
    ke_p = KeyExpansionMemoryAllocationBuild(TestVectors::key_128, 32, false);
    // Test invalid key length
    success = ASSERT_TRUE(ke_p == NULL, "Invalid key length should return null pointer") && success;
    KeyExpansionDelete(&ke_p);

    PRINT_RESULTS();
    return success;
}

bool test_encryptBlock() {
    TEST_SUITE("AES Block Encryption Tests");
    // Prepare key expansion
    KeyExpansion_ptr ke_p = KeyExpansionMemoryAllocationBuild(TestVectors::key_128, Nk128, false);
    Block* input = BlockMemoryAllocationFromBytes(TestVectors::plaintext);
    uint8_t BuffBlock[BLOCK_SIZE] = {0};
    Block* output = BlockMemoryAllocationFromBytes(BuffBlock);
    bool success = true;

    // Test single block encryption
    //ASSERT_TRUE(encryptBlock(input, ke_p, output, true) == false, "AES block encryption should succeed");
    encryptBlock(input, ke_p, output, true);
    bytesFromBlock(output, BuffBlock);

    success = success && ASSERT_BYTES_EQUAL(TestVectors::expected_ciphertext_128, BuffBlock, BLOCK_SIZE, "Encrypted block should match test vector");

    // Test null pointer handling
    //ASSERT_TRUE(aes_encrypt_block(nullptr, output, expanded_key, 10) != false, "Null input should return error");
    BlockDelete(&input);
    BlockDelete(&output);

    PRINT_RESULTS();
    return success;
}

bool test_decryptBlock() {
    TEST_SUITE("AES Block Decryption Tests");
    // Prepare key expansion
    KeyExpansion_ptr ke_p = KeyExpansionMemoryAllocationBuild(TestVectors::key_128, Nk128, false);
    Block* input = BlockMemoryAllocationFromBytes(TestVectors::expected_ciphertext_128);
    uint8_t BuffBlock[BLOCK_SIZE] = {0};
    Block* output = BlockMemoryAllocationFromBytes(BuffBlock);
    bool success = true;

    // Test single block encryption
    //ASSERT_TRUE(encryptBlock(input, ke_p, output, true) == false, "AES block encryption should succeed");
    decryptBlock(input, ke_p, output, true);
    bytesFromBlock(output, BuffBlock);

    success = success && ASSERT_BYTES_EQUAL(TestVectors::plaintext, BuffBlock, BLOCK_SIZE, "Decrypted block should match original plaintext");

    // Test null pointer handling
    //ASSERT_TRUE(aes_encrypt_block(nullptr, output, expanded_key, 10) != false, "Null input should return error");
    BlockDelete(&input);
    BlockDelete(&output);

    PRINT_RESULTS();
    return success;
}

bool test_encryptionDecryptionRoundtrip() {
    TEST_SUITE("AES Roundtrip Tests");
    // Prepare key expansion
    KeyExpansion_ptr ke_p = KeyExpansionMemoryAllocationBuild(TestVectors::key_128, Nk128, false);
    Block* input = BlockMemoryAllocationFromBytes(TestVectors::plaintext);
    uint8_t BuffBlock[BLOCK_SIZE] = {0};
    Block* encrypted = BlockMemoryAllocationFromBytes(BuffBlock);
    Block* decrypted = BlockMemoryAllocationFromBytes(BuffBlock);
    bool success = true;

    encryptBlock(input, ke_p, encrypted, true);
    decryptBlock(encrypted, ke_p, decrypted, true);
    bytesFromBlock(decrypted, BuffBlock);

    success = success && ASSERT_BYTES_EQUAL(TestVectors::plaintext, BuffBlock, BLOCK_SIZE, "Roundtrip encryption/decryption should preserve data");

    BlockDelete(&input);
    BlockDelete(&encrypted);
    BlockDelete(&decrypted);

    PRINT_RESULTS();
    return success;
}
