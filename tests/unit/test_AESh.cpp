// Tests for data-encryption/AES.h
#include"../include/NIST_FIPS197_TestVectors.hpp"
#include"../include/test_framework.hpp"
#include"../../data-encryption/include/AES.h"
#include"../../data-encryption/include/constants.h"
#include<cstring>

bool test_KeyExpansionMemoryAllocationBuild(Common::KeySize ks, bool debugHard);
bool test_encryptBlock(Common::KeySize ks, bool debugHard);
bool test_decryptBlock(Common::KeySize ks, bool debugHard);
bool test_encryptionDecryptionRoundtrip(Common::KeySize ks, bool debugHard);

/**
 * @brief Runs the complete set of AES tests for a specific key length.
 *
 * This function prints a banner for the key length and then executes the key
 * expansion, encryption, decryption, and roundtrip tests.
 *
 * @param ks The key size to test (e.g., Common::KeySize::AES128).
 * @param debugHard The debug flag to pass to the test functions.
 * @return true if the critical key expansion test passes, false otherwise.
 */
bool runTestsForKeySize(Common::KeySize ks, bool debugHard);

int main() {
    std::cout << "================= AES Core Implementation Tests =================\n" << std::endl;

    // The debug flag is set once and can be easily changed for all tests here.
    const bool debugMode = false;
    bool allTestsSucceed = true;

    allTestsSucceed &= runTestsForKeySize(Common::KeySize::AES128, debugMode);
    allTestsSucceed &= runTestsForKeySize(Common::KeySize::AES192, debugMode);
    allTestsSucceed &= runTestsForKeySize(Common::KeySize::AES256, debugMode);

    if(allTestsSucceed) {
        std::cout << "\n\n================== All AES Core Tests Succeed ==================" << std::endl;
        return 0; // Success
    } else {
        std::cout << "\n\n================== Some AES Core Tests Failed ==================" << std::endl;
        return 1; // Some tests failed
    }
}

// Test functions
bool test_KeyExpansionMemoryAllocationBuild(Common::KeySize ks, bool debugHard) {
    TEST_SUITE("AES Key Expansion Tests");

    bool success = true;
    // Building reference for our test
    FIPS197::KeyExpansion::TestVector reference(ks);
    // Casting key length
    size_t keylenbits = static_cast<size_t>(ks);
    // Building key
    ptrKeyExpansion_t ke_p = KeyExpansionMemoryAllocationBuild(reference.getKey(), keylenbits, debugHard);

    // Test key expansion for the specified key size
    // Wrapped in an if statement to guard against access to null pointer.
    if(!ASSERT_NOT_NULL(
        ke_p, "Key expansion should succeed"
    )) return false;

    size_t keyexpansionlen = getKeyExpansionLengthBytesfromKeylenBits(static_cast<KeylenBits_t>(keylenbits));
    std::vector<uint8_t> KeyExpansionBytes(keyexpansionlen);

    // Verify expanded key matches reference
    KeyExpansionWriteBytes(ke_p, KeyExpansionBytes.data());
    success &= ASSERT_BYTES_EQUAL(
        reference.getExpectedKeyExpansion(),
        KeyExpansionBytes.data(),
        keyexpansionlen,
        "Expanded key should match reference expanded key"
    );

    KeyExpansionDelete(&ke_p);

    // Try to build new key with invalid key length
    ke_p = KeyExpansionMemoryAllocationBuild(reference.getKey(), 1, debugHard);
    // Test invalid key length
    success &= ASSERT_TRUE(
        ke_p == NULL, "Invalid key length should return null pointer"
    );
    KeyExpansionDelete(&ke_p);

    PRINT_RESULTS();
    return success;
}

bool test_encryptBlock(Common::KeySize ks, bool debugHard) {
    TEST_SUITE("AES Block_t Encryption Tests");

    bool success = true;
    // Building reference for our test
    FIPS197::Encryption::TestVector reference(ks, Common::Direction::Encryption);
    // Casting key length
    size_t keylenbits = static_cast<size_t>(ks);
    // Building key
    ptrKeyExpansion_t ke_p = KeyExpansionMemoryAllocationBuild(reference.getKey(), keylenbits, debugHard);
    // Building input block
    Block_t* input = BlockMemoryAllocationFromBytes(reference.getInput());
    Block_t* output = BlockMemoryAllocationZero();
    uint8_t outputPlainBytes[BLOCK_SIZE] = {0};

    // Test single block encryption
    success &= ASSERT_TRUE(
        encryptBlock(input, ke_p, output, debugHard) == NoException, "AES block encryption should succeed"
    );
    encryptBlock(input, ke_p, output, debugHard);
    bytesFromBlock(output, outputPlainBytes);

    success &= ASSERT_BYTES_EQUAL(
        reference.getExpectedOutput(), outputPlainBytes, BLOCK_SIZE, "Encrypted block should match test vector"
    );

    // Test null pointer handling
    success &= ASSERT_TRUE(
        encryptBlock(NULL, ke_p, output, debugHard) != NoException, "Null input should return error"
    );
    BlockDelete(&output);
    BlockDelete(&input);
    KeyExpansionDelete(&ke_p);

    PRINT_RESULTS();
    return success;
}

bool test_decryptBlock(Common::KeySize ks, bool debugHard) {
    TEST_SUITE("AES Block_t Decryption Tests");

    bool success = true;
    // Building reference for our test
    FIPS197::Encryption::TestVector reference(ks, Common::Direction::Decryption);
    // Casting key length
    size_t keylenbits = static_cast<size_t>(ks);
    // Building key
    ptrKeyExpansion_t ke_p = KeyExpansionMemoryAllocationBuild(reference.getKey(), keylenbits, debugHard);
    // Building input block
    Block_t* input = BlockMemoryAllocationFromBytes(reference.getInput());
    Block_t* output = BlockMemoryAllocationZero();
    uint8_t outputPlainBytes[BLOCK_SIZE] = {0};

    // Test single block decryption
    success &= ASSERT_TRUE(
        decryptBlock(input, ke_p, output, debugHard) == NoException, "AES block decryption should succeed"
    );
    decryptBlock(input, ke_p, output, debugHard);
    bytesFromBlock(output, outputPlainBytes);

    success &= ASSERT_BYTES_EQUAL(
        reference.getExpectedOutput(), outputPlainBytes, BLOCK_SIZE, "Decrypted block should match original plaintext"
    );

    // Test null pointer handling
    success &= ASSERT_TRUE(
        decryptBlock(NULL, ke_p, output, debugHard) != NoException, "Null input should return error"
    );
    BlockDelete(&output);
    BlockDelete(&input);
    KeyExpansionDelete(&ke_p);

    PRINT_RESULTS();
    return success;
}

bool test_encryptionDecryptionRoundtrip(Common::KeySize ks, bool debugHard) {
    TEST_SUITE("AES Roundtrip Tests");

    bool success = true;
    // Building reference for our test
    FIPS197::Encryption::TestVector reference(ks, Common::Direction::Encryption);
    // Casting key length
    size_t keylenbits = static_cast<size_t>(ks);
    // Building key
    ptrKeyExpansion_t ke_p = KeyExpansionMemoryAllocationBuild(reference.getKey(), keylenbits, debugHard);
    // Building input block
    Block_t* input = BlockMemoryAllocationFromBytes(reference.getInput());
    Block_t* encrypted = BlockMemoryAllocationZero();
    Block_t* decrypted = BlockMemoryAllocationZero();
    uint8_t roundTripOutputBytes[BLOCK_SIZE] = {0};

    encryptBlock(input, ke_p, encrypted, debugHard);
    decryptBlock(encrypted, ke_p, decrypted, debugHard);
    bytesFromBlock(decrypted, roundTripOutputBytes);

    success &= ASSERT_BYTES_EQUAL(
        FIPS197::Encryption::plainText, roundTripOutputBytes, BLOCK_SIZE, "Roundtrip encryption/decryption should preserve data"
    );

    BlockDelete(&decrypted);
    BlockDelete(&encrypted);
    BlockDelete(&input);
    KeyExpansionDelete(&ke_p);

    PRINT_RESULTS();
    return success;
}

bool runTestsForKeySize(Common::KeySize ks, bool debugHard) {
    const char* keylenStr = Common::getKeySizeString(ks);
    bool success = true;
    std::cout << "\n=================================================================\n"
    << "\n======================= AES key " << keylenStr << " bits ========================\n"
    << "\n=================================================================\n" << std::endl;

    if (test_KeyExpansionMemoryAllocationBuild(ks, debugHard) == false) {
        std::cout << "\n=== Fail to create a valid Key Expansion object. Stop. ===" << std::endl;
        return false;
    }
    success &= test_encryptBlock(ks, debugHard);
    success &= test_decryptBlock(ks, debugHard);
    success &= test_encryptionDecryptionRoundtrip(ks, debugHard);

    std::cout << std::endl;
    return success;
}
