#include <gtest/gtest.h>
#include "../../core-crypto/aes/include/constants.h"
#include "../../core-crypto/aes/include/block.h"
#include "../../core-crypto/aes/include/key_expansion.h"
#include "../../core-crypto/aes/include/AES.h"
#include "../../core-crypto/aes/include/operation_modes.h"
#include "../../testing/include/test-vectors/sp800_38a_modes.hpp"
#include <cstring>

namespace TV = TestVectors::AES;
namespace SP = TestVectors::AES::SP800_38A;

void test_ecb_mode(TV::KeySize ks);
void test_cbc_mode(TV::KeySize ks);
void test_ofb_mode(TV::KeySize ks);
void test_ctr_mode(TV::KeySize ks);
void test_iv_independence(TV::KeySize ks);
void test_error_conditions(TV::KeySize ks);

void test_ecb_mode(TV::KeySize ks) {
    SP::ECB::TestVector example_ecb(ks, TV::Direction::Encrypt);
    const size_t expanded_key_len = getKeyExpansionLengthBytesfromKeylenBits(static_cast<KeylenBits_t>(ks));
    std::vector<uint8_t> expanded_key(expanded_key_len);
    uint8_t output[SP::kDataSize];
    uint8_t decrypted[SP::kDataSize];

    EXPECT_TRUE(
        KeyExpansionInitWrite(example_ecb.getKey().data(), static_cast<size_t>(ks), expanded_key.data(), false) == NoException)
        << "Key expansion should succeed";

    EXPECT_TRUE(
        encryptECB(example_ecb.getInput().data(), SP::kDataSize, expanded_key.data(), static_cast<KeylenBits_t>(ks), output) == NoException)
        << "ECB encryption should succeed";

    EXPECT_EQ(0, memcmp(example_ecb.getExpectedOutput().data(), output, SP::kDataSize))
        << "ECB encryption should match test vector";

    EXPECT_TRUE(
        decryptECB(output, SP::kDataSize, expanded_key.data(), static_cast<KeylenBits_t>(ks), decrypted) == NoException)
        << "ECB decryption should succeed";

    EXPECT_EQ(0, memcmp(SP::kPlainText, decrypted, SP::kDataSize))
        << "ECB roundtrip should preserve plaintext";
}

void test_cbc_mode(TV::KeySize ks) {
    SP::CBC::TestVector example_cbc(ks, TV::Direction::Encrypt);
    const size_t expanded_key_len = getKeyExpansionLengthBytesfromKeylenBits(static_cast<KeylenBits_t>(ks));
    std::vector<uint8_t> expanded_key(expanded_key_len);
    uint8_t output[SP::kDataSize];
    uint8_t decrypted[SP::kDataSize];

    EXPECT_TRUE(
        KeyExpansionInitWrite(example_cbc.getKey().data(), static_cast<size_t>(ks), expanded_key.data(), false) == NoException)
        << "Key expansion should succeed";

    EXPECT_TRUE(
        encryptCBC(SP::kPlainText, SP::kDataSize, expanded_key.data(), static_cast<KeylenBits_t>(ks), example_cbc.getIV().data(), output) == NoException)
        << "CBC encryption should succeed";

    EXPECT_EQ(0, memcmp(example_cbc.getExpectedOutput().data(), output, SP::kDataSize))
        << "CBC encryption should match test vector";

    EXPECT_TRUE(
        decryptCBC(output, SP::kDataSize, expanded_key.data(), static_cast<KeylenBits_t>(ks), example_cbc.getIV().data(), decrypted) == NoException)
        << "CBC decryption should succeed";

    EXPECT_EQ(0, memcmp(SP::kPlainText, decrypted, SP::kDataSize))
        << "CBC roundtrip should preserve plaintext";
}

void test_ofb_mode(TV::KeySize ks) {
    SP::OFB::TestVector example_ofb(ks, TV::Direction::Encrypt);
    const size_t expanded_key_len = getKeyExpansionLengthBytesfromKeylenBits(static_cast<KeylenBits_t>(ks));
    std::vector<uint8_t> expanded_key(expanded_key_len);
    uint8_t output[SP::kDataSize];
    uint8_t decrypted[SP::kDataSize];

    EXPECT_TRUE(
        KeyExpansionInitWrite(example_ofb.getKey().data(), static_cast<size_t>(ks), expanded_key.data(), false) == NoException)
        << "Key expansion should succeed";

    EXPECT_TRUE(
        encryptOFB(SP::kPlainText, SP::kDataSize, expanded_key.data(), static_cast<KeylenBits_t>(ks), example_ofb.getIV().data(), output) == NoException)
        << "OFB encryption should succeed";

    EXPECT_EQ(0, memcmp(example_ofb.getExpectedOutput().data(), output, SP::kDataSize))
        << "OFB encryption should match test vector";

    EXPECT_TRUE(
        decryptOFB(output, SP::kDataSize, expanded_key.data(), static_cast<KeylenBits_t>(ks), example_ofb.getIV().data(), decrypted) == NoException)
        << "OFB decryption should succeed";

    EXPECT_EQ(0, memcmp(SP::kPlainText, decrypted, SP::kDataSize))
        << "OFB roundtrip should preserve plaintext";
}

void test_ctr_mode(TV::KeySize ks) {
    SP::CTR::TestVector example_ctr(ks, TV::Direction::Encrypt);
    const size_t expanded_key_len = getKeyExpansionLengthBytesfromKeylenBits(static_cast<KeylenBits_t>(ks));
    std::vector<uint8_t> expanded_key(expanded_key_len);
    uint8_t output[SP::kDataSize];
    uint8_t decrypted[SP::kDataSize];

    EXPECT_TRUE(
        KeyExpansionInitWrite(example_ctr.getKey().data(), static_cast<size_t>(ks), expanded_key.data(), false) == NoException)
        << "Key expansion should succeed";

    EXPECT_TRUE(
        encryptCTR(SP::kPlainText, SP::kDataSize, expanded_key.data(), static_cast<KeylenBits_t>(ks), example_ctr.getCounter().data(), output) == NoException)
        << "CTR encryption should succeed";

    EXPECT_EQ(0, memcmp(example_ctr.getExpectedOutput().data(), output, SP::kDataSize))
        << "CTR encryption should match test vector";

    EXPECT_TRUE(
        decryptCTR(output, SP::kDataSize, expanded_key.data(), static_cast<KeylenBits_t>(ks), example_ctr.getCounter().data(), decrypted) == NoException)
        << "CTR decryption should succeed";

    EXPECT_EQ(0, memcmp(SP::kPlainText, decrypted, SP::kDataSize))
        << "CTR roundtrip should preserve plaintext";
}

void test_iv_independence(TV::KeySize ks) {
    SP::CBC::TestVector example_cbc(ks, TV::Direction::Encrypt);
    const size_t expanded_key_len = getKeyExpansionLengthBytesfromKeylenBits(static_cast<KeylenBits_t>(ks));
    std::vector<uint8_t> expanded_key(expanded_key_len);
    uint8_t output1[SP::kDataSize], output2[SP::kDataSize];
    uint8_t iv1[BLOCK_SIZE], iv2[BLOCK_SIZE];

    KeyExpansionInitWrite(example_cbc.getKey().data(), static_cast<size_t>(ks), expanded_key.data(), false);

    memcpy(iv1, example_cbc.getIV().data(), BLOCK_SIZE);
    memcpy(iv2, example_cbc.getIV().data(), BLOCK_SIZE);
    iv2[0] = 0xFF;

    encryptCBC(SP::kPlainText, SP::kDataSize, expanded_key.data(), static_cast<KeylenBits_t>(ks), iv1, output1);
    encryptCBC(SP::kPlainText, SP::kDataSize, expanded_key.data(), static_cast<KeylenBits_t>(ks), iv2, output2);

    EXPECT_TRUE(memcmp(output1, output2, SP::kDataSize) != 0)
        << "Different IVs should produce different ciphertext";
}

void test_error_conditions(TV::KeySize ks) {
    SP::ECB::TestVector example_ecb(ks, TV::Direction::Encrypt);
    SP::CBC::TestVector example_cbc(ks, TV::Direction::Encrypt);
    SP::OFB::TestVector example_ofb(ks, TV::Direction::Encrypt);
    SP::CTR::TestVector example_ctr(ks, TV::Direction::Encrypt);
    const size_t expanded_key_len = getKeyExpansionLengthBytesfromKeylenBits(static_cast<KeylenBits_t>(ks));
    std::vector<uint8_t> expanded_key(expanded_key_len);
    uint8_t output[SP::kDataSize];

    KeyExpansionInitWrite(example_ecb.getKey().data(), static_cast<size_t>(ks), expanded_key.data(), false);

    EXPECT_TRUE(encryptECB(NULL, SP::kDataSize, expanded_key.data(), static_cast<KeylenBits_t>(ks), output) != NoException)
        << "ECB should handle null input";
    EXPECT_TRUE(encryptECB(SP::kPlainText, SP::kDataSize, expanded_key.data(), static_cast<KeylenBits_t>(ks), NULL) != NoException)
        << "ECB should handle null output";

    EXPECT_TRUE(encryptCBC(NULL, SP::kDataSize, expanded_key.data(), static_cast<KeylenBits_t>(ks), example_cbc.getIV().data(), output) == NullInput)
        << "CBC should handle null input";
    EXPECT_TRUE(encryptCBC(SP::kPlainText, SP::kDataSize, expanded_key.data(), static_cast<KeylenBits_t>(ks), example_cbc.getIV().data(), NULL) == NullOutput)
        << "CBC should handle null output";
    EXPECT_TRUE(encryptCBC(SP::kPlainText, SP::kDataSize, expanded_key.data(), static_cast<KeylenBits_t>(ks), NULL, output) == NullInitialVector)
        << "CBC should handle null IV";

    EXPECT_TRUE(encryptECB(SP::kPlainText, 0, expanded_key.data(), static_cast<KeylenBits_t>(ks), output) == ZeroLength)
        << "ECB should handle zero length";
    EXPECT_TRUE(encryptCBC(SP::kPlainText, 0, expanded_key.data(), static_cast<KeylenBits_t>(ks), example_cbc.getIV().data(), output) == ZeroLength)
        << "CBC should handle zero length";

    EXPECT_TRUE(encryptOFB(NULL, SP::kDataSize, expanded_key.data(), static_cast<KeylenBits_t>(ks), example_ofb.getIV().data(), output) == NullInput)
        << "OFB should handle null input";
    EXPECT_TRUE(encryptOFB(SP::kPlainText, SP::kDataSize, expanded_key.data(), static_cast<KeylenBits_t>(ks), example_ofb.getIV().data(), NULL) == NullOutput)
        << "OFB should handle null output";
    EXPECT_TRUE(encryptOFB(SP::kPlainText, SP::kDataSize, expanded_key.data(), static_cast<KeylenBits_t>(ks), NULL, output) == NullInitialVector)
        << "OFB should handle null IV";
    EXPECT_TRUE(encryptOFB(SP::kPlainText, 0, expanded_key.data(), static_cast<KeylenBits_t>(ks), example_ofb.getIV().data(), output) == ZeroLength)
        << "OFB should handle zero length";

    EXPECT_TRUE(encryptCTR(NULL, SP::kDataSize, expanded_key.data(), static_cast<KeylenBits_t>(ks), example_ctr.getCounter().data(), output) == NullInput)
        << "CTR should handle null input";
    EXPECT_TRUE(encryptCTR(SP::kPlainText, SP::kDataSize, expanded_key.data(), static_cast<KeylenBits_t>(ks), example_ctr.getCounter().data(), NULL) == NullOutput)
        << "CTR should handle null output";
    EXPECT_TRUE(encryptCTR(SP::kPlainText, SP::kDataSize, expanded_key.data(), static_cast<KeylenBits_t>(ks), NULL, output) == NullInitialVector)
        << "CTR should handle null counter";
    EXPECT_TRUE(encryptCTR(SP::kPlainText, 0, expanded_key.data(), static_cast<KeylenBits_t>(ks), example_ctr.getCounter().data(), output) == ZeroLength)
        << "CTR should handle zero length";
}

// ── 18 TEST cases (3 key sizes × 6 test functions) ───────────────────────────

TEST(OperationModesTest, ECB_AES128)           { test_ecb_mode(TV::KeySize::AES128); }
TEST(OperationModesTest, ECB_AES192)           { test_ecb_mode(TV::KeySize::AES192); }
TEST(OperationModesTest, ECB_AES256)           { test_ecb_mode(TV::KeySize::AES256); }

TEST(OperationModesTest, CBC_AES128)           { test_cbc_mode(TV::KeySize::AES128); }
TEST(OperationModesTest, CBC_AES192)           { test_cbc_mode(TV::KeySize::AES192); }
TEST(OperationModesTest, CBC_AES256)           { test_cbc_mode(TV::KeySize::AES256); }

TEST(OperationModesTest, OFB_AES128)           { test_ofb_mode(TV::KeySize::AES128); }
TEST(OperationModesTest, OFB_AES192)           { test_ofb_mode(TV::KeySize::AES192); }
TEST(OperationModesTest, OFB_AES256)           { test_ofb_mode(TV::KeySize::AES256); }

TEST(OperationModesTest, CTR_AES128)           { test_ctr_mode(TV::KeySize::AES128); }
TEST(OperationModesTest, CTR_AES192)           { test_ctr_mode(TV::KeySize::AES192); }
TEST(OperationModesTest, CTR_AES256)           { test_ctr_mode(TV::KeySize::AES256); }

TEST(OperationModesTest, IVIndependence_AES128) { test_iv_independence(TV::KeySize::AES128); }
TEST(OperationModesTest, IVIndependence_AES192) { test_iv_independence(TV::KeySize::AES192); }
TEST(OperationModesTest, IVIndependence_AES256) { test_iv_independence(TV::KeySize::AES256); }

TEST(OperationModesTest, ErrorConditions_AES128) { test_error_conditions(TV::KeySize::AES128); }
TEST(OperationModesTest, ErrorConditions_AES192) { test_error_conditions(TV::KeySize::AES192); }
TEST(OperationModesTest, ErrorConditions_AES256) { test_error_conditions(TV::KeySize::AES256); }
