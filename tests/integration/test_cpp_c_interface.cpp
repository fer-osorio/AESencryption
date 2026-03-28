#include <gtest/gtest.h>
#include <cstring>
#include "../../core-crypto/aes/include/constants.h"
#include "../../core-crypto/aes/include/block.h"
#include "../../core-crypto/aes/include/key_expansion.h"
#include "../../core-crypto/aes/include/AES.h"
#include "../../core-crypto/aes/include/operation_modes.h"
#include "../../core-crypto/include/cipher.hpp"
#include "../../core-crypto/include/key.hpp"
#include "../../testing/include/test-vectors/sp800_38a_modes.hpp"

namespace TV = TestVectors::AES;
namespace SP = TestVectors::AES::SP800_38A;

#define AESKEY CipherFortis::Key
#define AESENC_KEYLEN CipherFortis::Key::LengthBits
#define AESCIPHER CipherFortis::Cipher
#define AESENC_OPTMODE CipherFortis::Cipher::OperationMode::Identifier

void test_specific_exception_code_mapping(AESENC_KEYLEN klb, AESENC_OPTMODE mode);
void test_key_expansion_initialization(AESENC_KEYLEN klb, AESENC_OPTMODE mode);
void test_consistency_with_c_implementation(AESENC_KEYLEN klb, AESENC_OPTMODE mode);

void test_specific_exception_code_mapping(AESENC_KEYLEN klb, AESENC_OPTMODE mode) {
    std::vector<uint8_t> dummy_key(static_cast<size_t>(klb)/8, 0);
    size_t c_klb = static_cast<size_t>(klb);
    KeyExpansion_t* c_ke = KeyExpansionCreate(dummy_key.data(), c_klb, false);
    size_t ke_lenbytes = getKeyExpansionLengthBytesfromKeylenBits(static_cast<enum KeylenBits_t>(c_klb));
    std::vector<uint8_t> c_key_expansion(ke_lenbytes);
    KeyExpansionWriteToBytes(c_ke, c_key_expansion.data());

    ASSERT_NE(c_ke, nullptr) << "Key expansion creation should succeed";

    const uint8_t* key_expansion_ptr = c_key_expansion.data();
    uint8_t input[BLOCK_SIZE];
    uint8_t output[BLOCK_SIZE];

    EXPECT_TRUE(encryptECB(nullptr, BLOCK_SIZE, key_expansion_ptr, c_klb, output) == NullInput)
        << "C function should return NullInput for null input";
    EXPECT_TRUE(encryptECB(input, BLOCK_SIZE, key_expansion_ptr, c_klb, nullptr) == NullOutput)
        << "C function should return NullOutput for null output";
    EXPECT_TRUE(encryptECB(input, 15, key_expansion_ptr, 128, output) == InvalidInputSize)
        << "C function should return InvalidInputSize for non-valid size";
    EXPECT_TRUE(encryptECB(input, 0, key_expansion_ptr, 128, output) == ZeroLength)
        << "C function should return ZeroLength for zero size";
    EXPECT_TRUE(encryptECB(input, BLOCK_SIZE, nullptr, 128, output) == NullSource)
        << "C function should return NullSource for null key expansion argument";

    KeyExpansionDestroy(&c_ke);
}

void test_key_expansion_initialization(AESENC_KEYLEN klb, AESENC_OPTMODE mode) {
    size_t keylen = static_cast<size_t>(klb);
    size_t ke_lenbytes = getKeyExpansionLengthBytesfromKeylenBits(static_cast<enum KeylenBits_t>(keylen));
    std::vector<uint8_t> dumm(keylen/8, 1);
    AESKEY key(dumm, klb);
    CipherFortis::Cipher cipher(key, AESCIPHER::OperationMode(mode));

    EXPECT_TRUE(cipher.isKeyExpansionInitialized())
        << "Key expansion should be initialized after construction";

    const uint8_t* key_expansion_ptr = cipher.getKeyExpansionForTesting();
    EXPECT_NE(key_expansion_ptr, nullptr) << "Key expansion pointer should not be null";

    KeyExpansion_t* c_ke = KeyExpansionCreate(dumm.data(), keylen, false);
    if (c_ke != nullptr) {
        std::vector<uint8_t> c_key_expansion(ke_lenbytes);
        KeyExpansionWriteToBytes(c_ke, c_key_expansion.data());

        EXPECT_EQ(0, memcmp(c_key_expansion.data(), key_expansion_ptr, BLOCK_SIZE))
            << "c key expansion and c++ key expansion should match";

        KeyExpansionDestroy(&c_ke);
    }
}

void test_consistency_with_c_implementation(AESENC_KEYLEN klb, AESENC_OPTMODE mode) {
    TV::KeySize ks;
    switch(klb) {
        case AESENC_KEYLEN::_128: ks = TV::KeySize::AES128; break;
        case AESENC_KEYLEN::_192: ks = TV::KeySize::AES192; break;
        case AESENC_KEYLEN::_256: ks = TV::KeySize::AES256; break;
        default: GTEST_FAIL() << "Unknown key size"; return;
    }

    TV::CipherMode cm;
    switch(mode) {
        case AESENC_OPTMODE::ECB: cm = TV::CipherMode::ECB; break;
        case AESENC_OPTMODE::CBC: cm = TV::CipherMode::CBC; break;
        default: GTEST_FAIL() << "Unsupported operation mode"; return;
    }

    std::unique_ptr<SP::ModeTestVectorBase> example = SP::create(ks, cm);
    ASSERT_NE(example, nullptr) << "Failed to create test vector";

    try {
        size_t sz_klb = static_cast<size_t>(klb);
        KeyExpansion_t* c_ke = KeyExpansionCreate(example->getKey().data(), sz_klb, false);
        ASSERT_NE(c_ke, nullptr) << "C key expansion creation should succeed";

        std::vector<uint8_t> key_expansion_bytes(getKeyExpansionLengthBytesfromKeylenBits(static_cast<KeylenBits_t>(klb)));
        KeyExpansionWriteToBytes(c_ke, key_expansion_bytes.data());
        uint8_t c_output[SP::kDataSize];

        AESKEY cpp_key(example->getKey(), klb);
        CipherFortis::Cipher cpp_cipher(cpp_key, AESCIPHER::OperationMode(mode));

        enum ExceptionCode c_result = [&]() -> enum ExceptionCode {
            switch(mode) {
                case AESENC_OPTMODE::ECB:
                    return encryptECB(example->getInput().data(), SP::kDataSize, key_expansion_bytes.data(), sz_klb, c_output);
                case AESENC_OPTMODE::CBC:
                    return encryptCBC(example->getInput().data(), SP::kDataSize, key_expansion_bytes.data(), sz_klb, cpp_cipher.getInitialVectorForTesting(), c_output);
                default:
                    return UnknownOperation;
            }
        }();
        EXPECT_TRUE(c_result == NoException) << "C encryption should succeed with NoException";

        uint8_t cpp_output[SP::kDataSize];
        cpp_cipher.encrypt(example->getInput().data(), SP::kDataSize, cpp_output);

        EXPECT_EQ(0, memcmp(c_output, cpp_output, SP::kDataSize))
            << "C++ wrapper should produce same result as direct C";

        uint8_t c_decrypted[SP::kDataSize];
        uint8_t cpp_decrypted[SP::kDataSize];

        c_result = [&]() -> enum ExceptionCode {
            switch(mode) {
                case AESENC_OPTMODE::ECB:
                    return decryptECB(c_output, SP::kDataSize, key_expansion_bytes.data(), sz_klb, c_decrypted);
                case AESENC_OPTMODE::CBC:
                    return decryptCBC(c_output, SP::kDataSize, key_expansion_bytes.data(), sz_klb, cpp_cipher.getInitialVectorForTesting(), c_decrypted);
                default:
                    return UnknownOperation;
            }
        }();
        EXPECT_TRUE(c_result == NoException) << "C decryption should succeed";

        cpp_cipher.decrypt(cpp_output, SP::kDataSize, cpp_decrypted);

        EXPECT_EQ(0, memcmp(c_decrypted, cpp_decrypted, SP::kDataSize))
            << "C++ and C decryption should produce same result";
        EXPECT_EQ(0, memcmp(example->getInput().data(), cpp_decrypted, SP::kDataSize))
            << "Both implementations should correctly decrypt data";

        KeyExpansionDestroy(&c_ke);
    } catch (const std::exception& e) {
        FAIL() << "Consistency test failed with exception: " << e.what();
    }
}

// ── 6 TEST cases (3 key sizes × 2 modes) ─────────────────────────────────────

TEST(CppCInterfaceTest, AES128_ECB) {
    test_specific_exception_code_mapping(AESENC_KEYLEN::_128, AESENC_OPTMODE::ECB);
    test_key_expansion_initialization(AESENC_KEYLEN::_128, AESENC_OPTMODE::ECB);
    test_consistency_with_c_implementation(AESENC_KEYLEN::_128, AESENC_OPTMODE::ECB);
}
TEST(CppCInterfaceTest, AES128_CBC) {
    test_specific_exception_code_mapping(AESENC_KEYLEN::_128, AESENC_OPTMODE::CBC);
    test_key_expansion_initialization(AESENC_KEYLEN::_128, AESENC_OPTMODE::CBC);
    test_consistency_with_c_implementation(AESENC_KEYLEN::_128, AESENC_OPTMODE::CBC);
}
TEST(CppCInterfaceTest, AES192_ECB) {
    test_specific_exception_code_mapping(AESENC_KEYLEN::_192, AESENC_OPTMODE::ECB);
    test_key_expansion_initialization(AESENC_KEYLEN::_192, AESENC_OPTMODE::ECB);
    test_consistency_with_c_implementation(AESENC_KEYLEN::_192, AESENC_OPTMODE::ECB);
}
TEST(CppCInterfaceTest, AES192_CBC) {
    test_specific_exception_code_mapping(AESENC_KEYLEN::_192, AESENC_OPTMODE::CBC);
    test_key_expansion_initialization(AESENC_KEYLEN::_192, AESENC_OPTMODE::CBC);
    test_consistency_with_c_implementation(AESENC_KEYLEN::_192, AESENC_OPTMODE::CBC);
}
TEST(CppCInterfaceTest, AES256_ECB) {
    test_specific_exception_code_mapping(AESENC_KEYLEN::_256, AESENC_OPTMODE::ECB);
    test_key_expansion_initialization(AESENC_KEYLEN::_256, AESENC_OPTMODE::ECB);
    test_consistency_with_c_implementation(AESENC_KEYLEN::_256, AESENC_OPTMODE::ECB);
}
TEST(CppCInterfaceTest, AES256_CBC) {
    test_specific_exception_code_mapping(AESENC_KEYLEN::_256, AESENC_OPTMODE::CBC);
    test_key_expansion_initialization(AESENC_KEYLEN::_256, AESENC_OPTMODE::CBC);
    test_consistency_with_c_implementation(AESENC_KEYLEN::_256, AESENC_OPTMODE::CBC);
}
