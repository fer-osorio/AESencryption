// Tests for data-encryption/AES.h
#include"../include/NIST_FIPS197_TestVectors.hpp"
#include"../include/test_framework.hpp"
#include"../../data-encryption/include/AES.h"
#include"../../data-encryption/include/constants.h"
#include<cstring>

bool test_KeyExpansionMemoryAllocationBuild(CommonAESVectors::KeylengthBits kl, bool debugHard);
bool test_encryptBlock(CommonAESVectors::KeylengthBits kl, bool debugHard);
bool test_decryptBlock(CommonAESVectors::KeylengthBits kl, bool debugHard);
bool test_encryptionDecryptionRoundtrip(CommonAESVectors::KeylengthBits kl, bool debugHard);

/**
 * @brief Runs the complete set of AES tests for a specific key length.
 *
 * This function prints a banner for the key length and then executes the key
 * expansion, encryption, decryption, and roundtrip tests.
 *
 * @param kl The key length to test (e.g., keylen128).
 * @param debugHard The debug flag to pass to the test functions.
 * @return true if the critical key expansion test passes, false otherwise.
 */
bool runTestsForKeylength(CommonAESVectors::KeylengthBits kl, bool debugHard);

int main() {
    std::cout << "================= AES Core Implementation Tests =================\n" << std::endl;

    // The debug flag is set once and can be easily changed for all tests here.
    const bool debugMode = false;

    if (!runTestsForKeylength(CommonAESVectors::KeylengthBits::keylen128, debugMode)) {
        return 1; // Exit with an error code on critical failure
    }

    if (!runTestsForKeylength(CommonAESVectors::KeylengthBits::keylen192, debugMode)) {
        return 1; // Exit with an error code on critical failure
    }

    if (!runTestsForKeylength(CommonAESVectors::KeylengthBits::keylen256, debugMode)) {
        return 1; // Exit with an error code on critical failure
    }

    std::cout << "\n\n================== All AES Core Tests Complete ==================" << std::endl;
    return 0; // Success
}

// Test functions
bool test_KeyExpansionMemoryAllocationBuild(CommonAESVectors::KeylengthBits kl, bool debugHard) {
    TEST_SUITE("AES Key Expansion Tests");

    bool success = true;
    // Building reference for out test
    NISTFIPS197_Examples::KeyExpansion_ns::Example reference(kl);
    // Casting key length
    size_t keylenbits = static_cast<size_t>(reference.getKeylenBits());
    // Buildgin key
    ptrKeyExpansion_t ke_p = KeyExpansionMemoryAllocationBuild(reference.getKey(), keylenbits, debugHard);

    // Test key expansion for 128-bit key
    // Wrapped in a if statement to guard agains access to null pointer.
    if(!ASSERT_NOT_NULL(ke_p, "AES-128 key expansion should succeed")) return false;

    size_t keyexpansionlen = getKeyExpansionLengthBytesfromKeylenBits(static_cast<KeylenBits_t>(kl));
    std::vector<uint8_t> KeyExpansionBytes(keyexpansionlen);

    // Verify first round key (should be original key)
    KeyExpansionWriteBytes(ke_p, KeyExpansionBytes.data());
    success = success &&
        ASSERT_BYTES_EQUAL(
            reference.getExpectedKeyExpansion(),
            KeyExpansionBytes.data(),
            keyexpansionlen,
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

bool test_encryptBlock(CommonAESVectors::KeylengthBits kl, bool debugHard) {
    TEST_SUITE("AES Block_t Encryption Tests");

    bool success = true;
    // Building reference for out test
    NISTFIPS197_Examples::Encryption_ns::Example reference(kl, CommonAESVectors::EncryptionOperationType::Encryption);
    // Casting key length
    size_t keylenbits = static_cast<size_t>(reference.getKeylenBits());
    // Buildgin key
    ptrKeyExpansion_t ke_p = KeyExpansionMemoryAllocationBuild(reference.getKey(), keylenbits, debugHard);
    // Building input block
    Block_t* input = BlockMemoryAllocationFromBytes(reference.getInput());
    Block_t* output = BlockMemoryAllocationZero();
    uint8_t outputPlainBytes[BLOCK_SIZE] = {0};

    // Test single block encryption
    ASSERT_TRUE(encryptBlock(input, ke_p, output, debugHard) == NoException, "AES block encryption should succeed");
    encryptBlock(input, ke_p, output, debugHard);
    bytesFromBlock(output, outputPlainBytes);

    success = ASSERT_BYTES_EQUAL(reference.getExpectedOutput(), outputPlainBytes, BLOCK_SIZE, "Encrypted block should match test vector") && success;

    // Test null pointer handling
    ASSERT_TRUE(encryptBlock(NULL, ke_p, output, debugHard) != NoException, "Null input should return error");
    BlockDelete(&output);
    BlockDelete(&input);
    KeyExpansionDelete(&ke_p);

    PRINT_RESULTS();
    return success;
}

bool test_decryptBlock(CommonAESVectors::KeylengthBits kl, bool debugHard) {
    TEST_SUITE("AES Block_t Decryption Tests");

    bool success = true;
    // Building reference for out test
    NISTFIPS197_Examples::Encryption_ns::Example reference(kl, CommonAESVectors::EncryptionOperationType::Decryption);
    // Casting key length
    size_t keylenbits = static_cast<size_t>(reference.getKeylenBits());
    // Buildgin key
    ptrKeyExpansion_t ke_p = KeyExpansionMemoryAllocationBuild(reference.getKey(), keylenbits, debugHard);
    // Building input block
    Block_t* input = BlockMemoryAllocationFromBytes(reference.getInput());
    Block_t* output = BlockMemoryAllocationZero();
    uint8_t outputPlainBytes[BLOCK_SIZE] = {0};

    // Test single block encryption
    ASSERT_TRUE(decryptBlock(input, ke_p, output, debugHard) == NoException, "AES block encryption should succeed");
    decryptBlock(input, ke_p, output, debugHard);
    bytesFromBlock(output, outputPlainBytes);

    success = ASSERT_BYTES_EQUAL(reference.getExpectedOutput(), outputPlainBytes, BLOCK_SIZE, "Decrypted block should match original plaintext") && success;

    // Test null pointer handling
    ASSERT_TRUE(decryptBlock(NULL, ke_p, output, debugHard) != NoException, "Null input should return error");
    BlockDelete(&output);
    BlockDelete(&input);
    KeyExpansionDelete(&ke_p);

    PRINT_RESULTS();
    return success;
}

bool test_encryptionDecryptionRoundtrip(CommonAESVectors::KeylengthBits kl, bool debugHard) {
    TEST_SUITE("AES Roundtrip Tests");

    bool success = true;
    // Building reference for out test
    NISTFIPS197_Examples::Encryption_ns::Example reference(kl, CommonAESVectors::EncryptionOperationType::Encryption);
    // Casting key length
    size_t keylenbits = static_cast<size_t>(reference.getKeylenBits());
    // Buildgin key
    ptrKeyExpansion_t ke_p = KeyExpansionMemoryAllocationBuild(reference.getKey(), keylenbits, debugHard);
    // Building input block
    Block_t* input = BlockMemoryAllocationFromBytes(reference.getInput());
    Block_t* encrypted = BlockMemoryAllocationZero();
    Block_t* decrypted = BlockMemoryAllocationZero();
    uint8_t roundTripOutputBytes[BLOCK_SIZE] = {0};

    encryptBlock(input, ke_p, encrypted, debugHard);
    decryptBlock(encrypted, ke_p, decrypted, debugHard);
    bytesFromBlock(decrypted, roundTripOutputBytes);

    success = ASSERT_BYTES_EQUAL(NISTFIPS197_Examples::Encryption_ns::plainText, roundTripOutputBytes, BLOCK_SIZE, "Roundtrip encryption/decryption should preserve data") && success;

    BlockDelete(&decrypted);
    BlockDelete(&encrypted);
    BlockDelete(&input);
    KeyExpansionDelete(&ke_p);

    PRINT_RESULTS();
    return success;
}

bool runTestsForKeylength(CommonAESVectors::KeylengthBits kl, bool debugHard) {
    const char* keylenStr = CommonAESVectors::getKeylengthString(kl);
    std::cout << "\n*****************************************************************\n"
              << "\n======================= AES key " << keylenStr << " bits ========================\n"
              << "\n*****************************************************************\n" << std::endl;

    if (test_KeyExpansionMemoryAllocationBuild(kl, debugHard) == false) {
        std::cout << "\n=== Fail to create a valid Key Expansion object. Stop. ===" << std::endl;
        return false;
    }
    test_encryptBlock(kl, debugHard);
    test_decryptBlock(kl, debugHard);
    test_encryptionDecryptionRoundtrip(kl, debugHard);

    std::cout << std::endl;
    return true;
}
