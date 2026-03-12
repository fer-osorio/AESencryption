#include"../../test-framework/include/test_framework.hpp"
#include"../../data-encryption/include/constants.h"
#include"../../data-encryption/include/block.h"
#include"../../data-encryption/include/key_expansion.h"
#include"../../data-encryption/include/AES.h"              // For encryptBlock/decryptBlock
#include"../../data-encryption/include/operation_modes.h"
#include"../../test-framework/include/test-vectors/sp800_38a_modes.hpp"
#include<cstring>

namespace TV = TestVectors::AES;
namespace SP = TestVectors::AES::SP800_38A;

bool test_ecb_mode(TV::KeySize ks);
bool test_cbc_mode(TV::KeySize ks);
bool test_ofb_mode(TV::KeySize ks);
bool test_ctr_mode(TV::KeySize ks);
bool test_iv_independence(TV::KeySize ks);
bool test_error_conditions(TV::KeySize ks);

/**
 * @brief Runs the complete set of AES Operation Modes tests for a specific key length.
 *
 * This function prints a banner for the key length and then executes the ecb,
 * cbc, iv independence and error condition tests.
 *
 * @param ks The key size to test (e.g., TV::KeySize::AES128).
 * @return true if all test pass, false otherwise.
 */
bool runTestsForKeylength(TV::KeySize ks);

int main() {
    std::cout << "===================== Operation Modes Tests =====================" << std::endl;
    bool allTestsSucceed = true;

    allTestsSucceed &= runTestsForKeylength(TV::KeySize::AES128);
    allTestsSucceed &= runTestsForKeylength(TV::KeySize::AES192);
    allTestsSucceed &= runTestsForKeylength(TV::KeySize::AES256);

    if(allTestsSucceed){
        std::cout << "\n===================== All Operation Modes Tests Succeed =====================" << std::endl;
        return 0;
    } else {
        std::cout << "\n===================== Some Operation Modes Tests Failed =====================" << std::endl;
        return 1;
    }
}

bool test_ecb_mode(TV::KeySize ks) {
    TEST_SUITE("ECB Mode Tests");

    bool successStatus = true;
    SP::ECB::TestVector example_ecb(ks, TV::Direction::Encrypt);
    const size_t expanded_key_len = getKeyExpansionLengthBytesfromKeylenBits(static_cast<KeylenBits_t>(ks));
    std::vector<uint8_t> expanded_key(expanded_key_len);                     // AES expanded key
    uint8_t output[SP::kDataSize];                          // 2 blocks
    uint8_t decrypted[SP::kDataSize];

    // Prepare key expansion
    successStatus = ASSERT_TRUE(
        KeyExpansionInitWrite(example_ecb.getKey().data(), static_cast<size_t>(ks), expanded_key.data(), false) == NoException,
        "Key expansion should succeed"
    ) && successStatus;

    // Test ECB encryption
    successStatus = ASSERT_TRUE(
        encryptECB(example_ecb.getInput().data(), SP::kDataSize, expanded_key.data(), static_cast<KeylenBits_t>(ks), output) == NoException,
        "ECB encryption should succeed"
    ) && successStatus;

    successStatus = ASSERT_BYTES_EQUAL(
        example_ecb.getExpectedOutput().data(), output, SP::kDataSize,
        "ECB encryption should match test vector"
    ) && successStatus;

    // Test ECB decryption
    successStatus = ASSERT_TRUE(
        decryptECB(output, SP::kDataSize, expanded_key.data(), static_cast<KeylenBits_t>(ks), decrypted) == NoException,
        "ECB decryption should succeed"
    ) && successStatus;

    successStatus = ASSERT_BYTES_EQUAL(
        SP::kPlainText, decrypted, SP::kDataSize,
        "ECB roundtrip should preserve plaintext"
    ) && successStatus;

    PRINT_RESULTS();

    return successStatus;
}

bool test_cbc_mode(TV::KeySize ks) {
    TEST_SUITE("CBC Mode Tests");

    bool successStatus = true;
    SP::CBC::TestVector example_cbc(ks, TV::Direction::Encrypt);
    const size_t expanded_key_len = getKeyExpansionLengthBytesfromKeylenBits(static_cast<KeylenBits_t>(ks));
    std::vector<uint8_t> expanded_key(expanded_key_len);
    uint8_t output[SP::kDataSize];
    uint8_t decrypted[SP::kDataSize];

    // Prepare key expansion
    successStatus = ASSERT_TRUE(
        KeyExpansionInitWrite(example_cbc.getKey().data(), static_cast<size_t>(ks), expanded_key.data(), false) == NoException,
        "Key expansion should succeed"
    ) && successStatus;

    successStatus = ASSERT_TRUE(
        encryptCBC(SP::kPlainText, SP::kDataSize, expanded_key.data(), static_cast<KeylenBits_t>(ks), example_cbc.getIV().data(), output) == NoException,
        "CBC encryption should succeed"
    ) && successStatus;

    successStatus = ASSERT_BYTES_EQUAL(
        example_cbc.getExpectedOutput().data(), output, SP::kDataSize,
        "CBC encryption should match test vector"
    ) && successStatus;

    // Test CBC decryption
    successStatus = ASSERT_TRUE(
        decryptCBC(output, SP::kDataSize, expanded_key.data(), static_cast<KeylenBits_t>(ks), example_cbc.getIV().data(), decrypted) == NoException,
        "CBC decryption should succeed"
    ) && successStatus;

    successStatus = ASSERT_BYTES_EQUAL(
        SP::kPlainText, decrypted, SP::kDataSize,
        "CBC roundtrip should preserve plaintext"
    ) && successStatus;

    PRINT_RESULTS();

    return successStatus;
}

bool test_ofb_mode(TV::KeySize ks) {
    TEST_SUITE("OFB Mode Tests");

    bool successStatus = true;
    SP::OFB::TestVector example_ofb(ks, TV::Direction::Encrypt);
    const size_t expanded_key_len = getKeyExpansionLengthBytesfromKeylenBits(static_cast<KeylenBits_t>(ks));
    std::vector<uint8_t> expanded_key(expanded_key_len);
    uint8_t output[SP::kDataSize];
    uint8_t decrypted[SP::kDataSize];

    // Prepare key expansion
    successStatus = ASSERT_TRUE(
        KeyExpansionInitWrite(example_ofb.getKey().data(), static_cast<size_t>(ks), expanded_key.data(), false) == NoException,
        "Key expansion should succeed"
    ) && successStatus;

    // Test OFB encryption
    successStatus = ASSERT_TRUE(
        encryptOFB(SP::kPlainText, SP::kDataSize, expanded_key.data(), static_cast<KeylenBits_t>(ks), example_ofb.getIV().data(), output) == NoException,
        "OFB encryption should succeed"
    ) && successStatus;

    successStatus = ASSERT_BYTES_EQUAL(
        example_ofb.getExpectedOutput().data(), output, SP::kDataSize,
        "OFB encryption should match test vector"
    ) && successStatus;

    // Test OFB decryption (round-trip)
    successStatus = ASSERT_TRUE(
        decryptOFB(output, SP::kDataSize, expanded_key.data(), static_cast<KeylenBits_t>(ks), example_ofb.getIV().data(), decrypted) == NoException,
        "OFB decryption should succeed"
    ) && successStatus;

    successStatus = ASSERT_BYTES_EQUAL(
        SP::kPlainText, decrypted, SP::kDataSize,
        "OFB roundtrip should preserve plaintext"
    ) && successStatus;

    PRINT_RESULTS();

    return successStatus;
}

bool test_ctr_mode(TV::KeySize ks) {
    TEST_SUITE("CTR Mode Tests");

    bool successStatus = true;
    SP::CTR::TestVector example_ctr(ks, TV::Direction::Encrypt);
    const size_t expanded_key_len = getKeyExpansionLengthBytesfromKeylenBits(static_cast<KeylenBits_t>(ks));
    std::vector<uint8_t> expanded_key(expanded_key_len);
    uint8_t output[SP::kDataSize];
    uint8_t decrypted[SP::kDataSize];

    // Prepare key expansion
    successStatus = ASSERT_TRUE(
        KeyExpansionInitWrite(example_ctr.getKey().data(), static_cast<size_t>(ks), expanded_key.data(), false) == NoException,
        "Key expansion should succeed"
    ) && successStatus;

    // Test CTR encryption
    successStatus = ASSERT_TRUE(
        encryptCTR(SP::kPlainText, SP::kDataSize, expanded_key.data(), static_cast<KeylenBits_t>(ks), example_ctr.getCounter().data(), output) == NoException,
        "CTR encryption should succeed"
    ) && successStatus;

    successStatus = ASSERT_BYTES_EQUAL(
        example_ctr.getExpectedOutput().data(), output, SP::kDataSize,
        "CTR encryption should match test vector"
    ) && successStatus;

    // Test CTR decryption (round-trip)
    successStatus = ASSERT_TRUE(
        decryptCTR(output, SP::kDataSize, expanded_key.data(), static_cast<KeylenBits_t>(ks), example_ctr.getCounter().data(), decrypted) == NoException,
        "CTR decryption should succeed"
    ) && successStatus;

    successStatus = ASSERT_BYTES_EQUAL(
        SP::kPlainText, decrypted, SP::kDataSize,
        "CTR roundtrip should preserve plaintext"
    ) && successStatus;

    PRINT_RESULTS();

    return successStatus;
}

bool test_iv_independence(TV::KeySize ks) {
    TEST_SUITE("IV Independence Tests");

    bool successStatus = true;
    SP::CBC::TestVector example_cbc(ks, TV::Direction::Encrypt);
    const size_t expanded_key_len = getKeyExpansionLengthBytesfromKeylenBits(static_cast<KeylenBits_t>(ks));
    std::vector<uint8_t> expanded_key(expanded_key_len);
    uint8_t output1[SP::kDataSize], output2[SP::kDataSize];
    uint8_t iv1[BLOCK_SIZE], iv2[BLOCK_SIZE];

    KeyExpansionInitWrite(example_cbc.getKey().data(), static_cast<size_t>(ks), expanded_key.data(), false);

    // Set up two different IVs
    memcpy(iv1, example_cbc.getIV().data(), BLOCK_SIZE);
    memcpy(iv2, example_cbc.getIV().data(), BLOCK_SIZE);
    iv2[0] = 0xFF; // Make second IV different

    // Encrypt same plaintext with different IVs
    encryptCBC(SP::kPlainText, SP::kDataSize, expanded_key.data(), static_cast<KeylenBits_t>(ks), iv1, output1);
    encryptCBC(SP::kPlainText, SP::kDataSize, expanded_key.data(), static_cast<KeylenBits_t>(ks), iv2, output2);

    successStatus = ASSERT_TRUE(
        memcmp(output1, output2, SP::kDataSize) != 0,
        "Different IVs should produce different ciphertext"
    );

    PRINT_RESULTS();

    return successStatus;
}

bool test_error_conditions(TV::KeySize ks) {
    TEST_SUITE("Error Condition Tests");

    bool successStatus = true;
    SP::ECB::TestVector example_ecb(ks, TV::Direction::Encrypt);
    SP::CBC::TestVector example_cbc(ks, TV::Direction::Encrypt);
    SP::OFB::TestVector example_ofb(ks, TV::Direction::Encrypt);
    SP::CTR::TestVector example_ctr(ks, TV::Direction::Encrypt);
    const size_t expanded_key_len = getKeyExpansionLengthBytesfromKeylenBits(static_cast<KeylenBits_t>(ks));
    std::vector<uint8_t> expanded_key(expanded_key_len);
    uint8_t output[SP::kDataSize];

    KeyExpansionInitWrite(example_ecb.getKey().data(), static_cast<size_t>(ks), expanded_key.data(), false);

    // Test null pointer handling
    successStatus = ASSERT_TRUE(
        encryptECB(NULL, SP::kDataSize, expanded_key.data(), static_cast<KeylenBits_t>(ks), output) != NoException,
        "ECB should handle null input"
    ) && successStatus;

    successStatus = ASSERT_TRUE(
        encryptECB(SP::kPlainText, SP::kDataSize, expanded_key.data(), static_cast<KeylenBits_t>(ks), NULL) != NoException,
        "ECB should handle null output"
    ) && successStatus;

    successStatus = ASSERT_TRUE(
        encryptCBC(NULL, SP::kDataSize, expanded_key.data(), static_cast<KeylenBits_t>(ks), example_cbc.getIV().data(), output) == NullInput,
        "CBC should handle null input"
    ) && successStatus;

    successStatus = ASSERT_TRUE(
        encryptCBC(SP::kPlainText, SP::kDataSize, expanded_key.data(), static_cast<KeylenBits_t>(ks), example_cbc.getIV().data(), NULL) == NullOutput,
        "CBC should handle null output"
    ) && successStatus;

    successStatus = ASSERT_TRUE(
        encryptCBC(SP::kPlainText, SP::kDataSize, expanded_key.data(), static_cast<KeylenBits_t>(ks), NULL, output) == NullInitialVector,
        "CBC should handle null IV"
    ) && successStatus;

    // Test zero length
    successStatus = ASSERT_TRUE(
        encryptECB(SP::kPlainText, 0, expanded_key.data(), static_cast<KeylenBits_t>(ks), output) == ZeroLength,
        "ECB should handle zero length"
    ) && successStatus;

    successStatus = ASSERT_TRUE(
        encryptCBC(SP::kPlainText, 0, expanded_key.data(), static_cast<KeylenBits_t>(ks), example_cbc.getIV().data(), output) == ZeroLength,
        "CBC should handle zero length"
    ) && successStatus;

    successStatus = ASSERT_TRUE(
        encryptOFB(NULL, SP::kDataSize, expanded_key.data(), static_cast<KeylenBits_t>(ks), example_ofb.getIV().data(), output) == NullInput,
        "OFB should handle null input"
    ) && successStatus;

    successStatus = ASSERT_TRUE(
        encryptOFB(SP::kPlainText, SP::kDataSize, expanded_key.data(), static_cast<KeylenBits_t>(ks), example_ofb.getIV().data(), NULL) == NullOutput,
        "OFB should handle null output"
    ) && successStatus;

    successStatus = ASSERT_TRUE(
        encryptOFB(SP::kPlainText, SP::kDataSize, expanded_key.data(), static_cast<KeylenBits_t>(ks), NULL, output) == NullInitialVector,
        "OFB should handle null IV"
    ) && successStatus;

    successStatus = ASSERT_TRUE(
        encryptOFB(SP::kPlainText, 0, expanded_key.data(), static_cast<KeylenBits_t>(ks), example_ofb.getIV().data(), output) == ZeroLength,
        "OFB should handle zero length"
    ) && successStatus;

    successStatus = ASSERT_TRUE(
        encryptCTR(NULL, SP::kDataSize, expanded_key.data(), static_cast<KeylenBits_t>(ks), example_ctr.getCounter().data(), output) == NullInput,
        "CTR should handle null input"
    ) && successStatus;

    successStatus = ASSERT_TRUE(
        encryptCTR(SP::kPlainText, SP::kDataSize, expanded_key.data(), static_cast<KeylenBits_t>(ks), example_ctr.getCounter().data(), NULL) == NullOutput,
        "CTR should handle null output"
    ) && successStatus;

    successStatus = ASSERT_TRUE(
        encryptCTR(SP::kPlainText, SP::kDataSize, expanded_key.data(), static_cast<KeylenBits_t>(ks), NULL, output) == NullInitialVector,
        "CTR should handle null counter"
    ) && successStatus;

    successStatus = ASSERT_TRUE(
        encryptCTR(SP::kPlainText, 0, expanded_key.data(), static_cast<KeylenBits_t>(ks), example_ctr.getCounter().data(), output) == ZeroLength,
        "CTR should handle zero length"
    ) && successStatus;

    PRINT_RESULTS();

    return successStatus;
}

bool runTestsForKeylength(TV::KeySize ks) {
    const char* keylenStr = TV::getKeySizeString(ks);
    bool successStatus = true;
    std::cout << "\n=================================================================\n"
    << "\n======================= AES key " << keylenStr << " bits ========================\n"
    << "\n=================================================================\n" << std::endl;

    successStatus = test_ecb_mode(ks) && successStatus;
    successStatus = test_cbc_mode(ks) && successStatus;
    successStatus = test_ofb_mode(ks) && successStatus;
    successStatus = test_ctr_mode(ks) && successStatus;
    successStatus = test_iv_independence(ks) && successStatus;
    successStatus = test_error_conditions(ks) && successStatus;

    std::cout << std::endl;
    return successStatus;
}
