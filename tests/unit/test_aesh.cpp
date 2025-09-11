// Tests for data-encryption/AES.h
#include"../include/fips197examples.hpp"
#include"../include/test_framework.hpp"
#include"../../data-encryption/include/AES.h"
#include"../../data-encryption/include/constants.h"
#include<cstring>

bool test_KeyExpansionMemoryAllocationBuild(FIPS197examples::KeylengthBits kl, bool debugHard);
bool test_encryptBlock(FIPS197examples::KeylengthBits kl, bool debugHard);
bool test_decryptBlock(FIPS197examples::KeylengthBits kl, bool debugHard);
bool test_encryptionDecryptionRoundtrip(FIPS197examples::KeylengthBits kl, bool debugHard);

int main() {
    std::cout << "=== AES Core Implementation Tests ===" << std::endl;

    if(test_KeyExpansionMemoryAllocationBuild(FIPS197examples::KeylengthBits::keylen192, false) == false) {
        std::cout << "\n=== Fail to create a valid Key Expansion object. Stop. ===" << std::endl;
        return 0;
    }
    test_encryptBlock(FIPS197examples::KeylengthBits::keylen192, false);
    test_decryptBlock(FIPS197examples::KeylengthBits::keylen192, false);
    test_encryptionDecryptionRoundtrip(FIPS197examples::KeylengthBits::keylen192, false);

    std::cout << "\n=== All AES Core Tests Complete ===" << std::endl;
    return 0;
}

// Test functions
bool test_KeyExpansionMemoryAllocationBuild(FIPS197examples::KeylengthBits kl, bool debugHard) {
    TEST_SUITE("AES Key Expansion Tests");

    bool success = true;
    // Building reference for out test
    FIPS197examples::KeyExpansion_ns::Example reference(kl);
    // Casting key length
    size_t keylenbits = static_cast<size_t>(reference.getKeylenBits());
    // Buildgin key|
    KeyExpansion_ptr ke_p = KeyExpansionMemoryAllocationBuild(reference.getKey(), keylenbits, debugHard);

    // Test key expansion for 128-bit key
    // Wrapped in a if statement to guard agains access to null pointer.
    if(!ASSERT_NOT_NULL(ke_p, "AES-128 key expansion should succeed")) return false;

    std::vector<uint8_t> KeyExpansionBytes(keylenbits/8);

    // Verify first round key (should be original key)
    KeyExpansionWriteBytes(ke_p, KeyExpansionBytes.data());
    success = success &&
        ASSERT_BYTES_EQUAL(
            reference.getExpectedKeyExpansion(),
            KeyExpansionBytes.data(),
            KEY_EXPANSION_LENGTH_128_BYTES,
            "Expanded key should match referece expanded key"
        );

    KeyExpansionDelete(&ke_p);

    // Try to build new key with invalid key length
    ke_p = KeyExpansionMemoryAllocationBuild(reference.getKey(), 1, debugHard);
    // Test invalid key length
    success = ASSERT_TRUE(ke_p == NULL, "Invalid key length should return null pointer") && success;
    KeyExpansionDelete(&ke_p);

    PRINT_RESULTS();
    return success;
}

bool test_encryptBlock(FIPS197examples::KeylengthBits kl, bool debugHard) {
    TEST_SUITE("AES Block Encryption Tests");

    bool success = true;
    // Building reference for out test
    FIPS197examples::Encryption_ns::Example reference(kl, FIPS197examples::Encryption_ns::Example::Classification::Encryption);
    // Casting key length
    size_t keylenbits = static_cast<size_t>(reference.getKeylenBits());
    // Buildgin key
    KeyExpansion_ptr ke_p = KeyExpansionMemoryAllocationBuild(reference.getKey(), keylenbits, debugHard);
    // Building input block
    Block* input = BlockMemoryAllocationFromBytes(reference.getInput());
    uint8_t BuffBlock[BLOCK_SIZE] = {0};
    Block* output = BlockMemoryAllocationFromBytes(BuffBlock);

    // Test single block encryption
    //ASSERT_TRUE(encryptBlock(input, ke_p, output, true) == false, "AES block encryption should succeed");
    encryptBlock(input, ke_p, output, debugHard);
    bytesFromBlock(output, BuffBlock);

    success = ASSERT_BYTES_EQUAL(reference.getExpectedOutput(), BuffBlock, BLOCK_SIZE, "Encrypted block should match test vector") && success;

    // Test null pointer handling
    //ASSERT_TRUE(aes_encrypt_block(nullptr, output, expanded_key, 10) != false, "Null input should return error");
    BlockDelete(&output);
    BlockDelete(&input);
    KeyExpansionDelete(&ke_p);

    PRINT_RESULTS();
    return success;
}

bool test_decryptBlock(FIPS197examples::KeylengthBits kl, bool debugHard) {
    TEST_SUITE("AES Block Decryption Tests");

    bool success = true;
    // Building reference for out test
    FIPS197examples::Encryption_ns::Example reference(kl, FIPS197examples::Encryption_ns::Example::Classification::Decryption);
    // Casting key length
    size_t keylenbits = static_cast<size_t>(reference.getKeylenBits());
    // Buildgin key
    KeyExpansion_ptr ke_p = KeyExpansionMemoryAllocationBuild(reference.getKey(), keylenbits, debugHard);
    // Building input block
    Block* input = BlockMemoryAllocationFromBytes(reference.getInput());
    uint8_t BuffBlock[BLOCK_SIZE] = {0};
    Block* output = BlockMemoryAllocationFromBytes(BuffBlock);

    // Test single block encryption
    //ASSERT_TRUE(encryptBlock(input, ke_p, output, true) == false, "AES block encryption should succeed");
    decryptBlock(input, ke_p, output, debugHard);
    bytesFromBlock(output, BuffBlock);

    success = ASSERT_BYTES_EQUAL(reference.getExpectedOutput(), BuffBlock, BLOCK_SIZE, "Decrypted block should match original plaintext") && success;

    // Test null pointer handling
    //ASSERT_TRUE(aes_encrypt_block(nullptr, output, expanded_key, 10) != false, "Null input should return error");
    BlockDelete(&output);
    BlockDelete(&input);
    KeyExpansionDelete(&ke_p);

    PRINT_RESULTS();
    return success;
}

bool test_encryptionDecryptionRoundtrip(FIPS197examples::KeylengthBits kl, bool debugHard) {
    TEST_SUITE("AES Roundtrip Tests");

    bool success = true;
    // Building reference for out test
    FIPS197examples::Encryption_ns::Example reference(kl, FIPS197examples::Encryption_ns::Example::Classification::Encryption);
    // Casting key length
    size_t keylenbits = static_cast<size_t>(reference.getKeylenBits());
    // Buildgin key
    KeyExpansion_ptr ke_p = KeyExpansionMemoryAllocationBuild(reference.getKey(), keylenbits, debugHard);
    // Building input block
    Block* input = BlockMemoryAllocationFromBytes(reference.getInput());
    uint8_t BuffBlock[BLOCK_SIZE] = {0};
    Block* encrypted = BlockMemoryAllocationFromBytes(BuffBlock);
    Block* decrypted = BlockMemoryAllocationFromBytes(BuffBlock);

    encryptBlock(input, ke_p, encrypted, debugHard);
    decryptBlock(encrypted, ke_p, decrypted, debugHard);
    bytesFromBlock(decrypted, BuffBlock);

    success = ASSERT_BYTES_EQUAL(FIPS197examples::Encryption_ns::plainText, BuffBlock, BLOCK_SIZE, "Roundtrip encryption/decryption should preserve data") && success;

    BlockDelete(&decrypted);
    BlockDelete(&encrypted);
    BlockDelete(&input);
    KeyExpansionDelete(&ke_p);

    PRINT_RESULTS();
    return success;
}
