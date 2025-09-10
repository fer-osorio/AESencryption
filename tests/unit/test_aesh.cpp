// Tests for data-encryption/AES.h
#include"../include/fips197examples.hpp"
#include"../include/test_framework.hpp"
#include"../../data-encryption/include/AES.h"
#include"../../data-encryption/include/constants.h"
#include<cstring>

bool test_KeyExpansionMemoryAllocationBuild(FIPS197examples::Keylen kl, bool debugHard);
bool test_encryptBlock(FIPS197examples::Keylen kl, bool debugHard);
bool test_decryptBlock(FIPS197examples::Keylen kl, bool debugHard);
bool test_encryptionDecryptionRoundtrip(FIPS197examples::Keylen kl, bool debugHard);

int main() {
    std::cout << "=== AES Core Implementation Tests ===" << std::endl;

    if(test_KeyExpansionMemoryAllocationBuild(false) == false) {
        std::cout << "\n=== Fail to create a valid Key Expansion object. Stop. ===" << std::endl;
        return 0;
    }
    test_encryptBlock(false);
    test_decryptBlock(false);
    test_encryptionDecryptionRoundtrip(false);

    std::cout << "\n=== All AES Core Tests Complete ===" << std::endl;
    return 0;
}

// Test functions
bool test_KeyExpansionMemoryAllocationBuild(FIPS197examples::Keylen kl, bool debugHard) {
    TEST_SUITE("AES Key Expansion Tests");
    FIPS197examples::Example e = FIPS197examples::Example::getExample(FIPS197examples::Classification::KeyExpansion,kl);
    KeyExpansion_ptr ke_p = KeyExpansionMemoryAllocationBuild(Example::Key::aes128_key, Keylenbits128, debugHard);
    uint8_t KeyExpansionBytesBuffer[KEY_EXPANSION_LENGTH_256_BYTES];
    bool success = true;

    // Test key expansion for 128-bit key
    // Wrapped in a if statement to guard agains access to null pointer.
    if(!ASSERT_NOT_NULL(ke_p, "AES-128 key expansion should succeed")) return false;

    // Verify first round key (should be original key)
    KeyExpansionWriteBytes(ke_p, KeyExpansionBytesBuffer);
    success = success &&
        ASSERT_BYTES_EQUAL(
            Example::ExpandedKey::aes128_key_expanded,
            KeyExpansionBytesBuffer,
            KEY_EXPANSION_LENGTH_128_BYTES,
            "Expanded key should match referece expanded key"
        );

    KeyExpansionDelete(&ke_p);

    // Try to build new key with invalid key length
    ke_p = KeyExpansionMemoryAllocationBuild(Example::Key::aes128_key, 3, debugHard);
    // Test invalid key length
    success = ASSERT_TRUE(ke_p == NULL, "Invalid key length should return null pointer") && success;
    KeyExpansionDelete(&ke_p);

    PRINT_RESULTS();
    return success;
}

bool test_encryptBlock(FIPS197examples::Keylen kl, bool debugHard) {
    TEST_SUITE("AES Block Encryption Tests");
    // Prepare key expansion
    KeyExpansion_ptr ke_p = KeyExpansionMemoryAllocationBuild(Example::Vector::key128, Keylenbits128, debugHard);
    Block* input = BlockMemoryAllocationFromBytes(Example::Vector::plainText);
    uint8_t BuffBlock[BLOCK_SIZE] = {0};
    Block* output = BlockMemoryAllocationFromBytes(BuffBlock);
    bool success = true;

    // Test single block encryption
    //ASSERT_TRUE(encryptBlock(input, ke_p, output, true) == false, "AES block encryption should succeed");
    encryptBlock(input, ke_p, output, debugHard);
    bytesFromBlock(output, BuffBlock);

    success = ASSERT_BYTES_EQUAL(Example::Vector::cipherTextKey128, BuffBlock, BLOCK_SIZE, "Encrypted block should match test vector") && success;

    // Test null pointer handling
    //ASSERT_TRUE(aes_encrypt_block(nullptr, output, expanded_key, 10) != false, "Null input should return error");
    BlockDelete(&output);
    BlockDelete(&input);
    KeyExpansionDelete(&ke_p);

    PRINT_RESULTS();
    return success;
}

bool test_decryptBlock(FIPS197examples::Keylen kl, bool debugHard) {
    TEST_SUITE("AES Block Decryption Tests");
    // Prepare key expansion
    KeyExpansion_ptr ke_p = KeyExpansionMemoryAllocationBuild(Example::Vector::key128, Keylenbits128, debugHard);
    Block* input = BlockMemoryAllocationFromBytes(Example::Vector::cipherTextKey128);
    uint8_t BuffBlock[BLOCK_SIZE] = {0};
    Block* output = BlockMemoryAllocationFromBytes(BuffBlock);
    bool success = true;

    // Test single block encryption
    //ASSERT_TRUE(encryptBlock(input, ke_p, output, true) == false, "AES block encryption should succeed");
    decryptBlock(input, ke_p, output, debugHard);
    bytesFromBlock(output, BuffBlock);

    success = ASSERT_BYTES_EQUAL(Example::Vector::plainText, BuffBlock, BLOCK_SIZE, "Decrypted block should match original plaintext") && success;

    // Test null pointer handling
    //ASSERT_TRUE(aes_encrypt_block(nullptr, output, expanded_key, 10) != false, "Null input should return error");
    BlockDelete(&output);
    BlockDelete(&input);
    KeyExpansionDelete(&ke_p);

    PRINT_RESULTS();
    return success;
}

bool test_encryptionDecryptionRoundtrip(FIPS197examples::Keylen kl, bool debugHard) {
    TEST_SUITE("AES Roundtrip Tests");
    // Prepare key expansion
    KeyExpansion_ptr ke_p = KeyExpansionMemoryAllocationBuild(Example::Vector::key128, Keylenbits128, debugHard);
    Block* input = BlockMemoryAllocationFromBytes(Example::Vector::plainText);
    uint8_t BuffBlock[BLOCK_SIZE] = {0};
    Block* encrypted = BlockMemoryAllocationFromBytes(BuffBlock);
    Block* decrypted = BlockMemoryAllocationFromBytes(BuffBlock);
    bool success = true;

    encryptBlock(input, ke_p, encrypted, debugHard);
    decryptBlock(encrypted, ke_p, decrypted, debugHard);
    bytesFromBlock(decrypted, BuffBlock);

    success = ASSERT_BYTES_EQUAL(Example::Vector::plainText, BuffBlock, BLOCK_SIZE, "Roundtrip encryption/decryption should preserve data") && success;

    BlockDelete(&decrypted);
    BlockDelete(&encrypted);
    BlockDelete(&input);
    KeyExpansionDelete(&ke_p);

    PRINT_RESULTS();
    return success;
}
