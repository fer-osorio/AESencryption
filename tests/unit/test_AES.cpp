#include <gtest/gtest.h>
#include "../../testing/include/test-encryption/detail/block_cipher_tester.hpp"
#include "../../core-crypto/aes/include/block.h"
#include "../../core-crypto/aes/include/key_expansion.h"
#include "../../core-crypto/aes/include/AES.h"

static KeyExpansion_t* (*allocateKeyExapansion)(size_t)      = KeyExpansionCreateZero;
static void            (*freeKeyExpansion)(KeyExpansion_t**) = KeyExpansionDestroy;
static Block_t*        (*allocateBlock)()                    = BlockCreateZero;
static void            (*freeBlock)(Block_t**)               = BlockDestroy;

CryptoTest::BlockCipher::MemoryCallbacks<KeyExpansion_t, Block_t> callbacks{
    allocateKeyExapansion,
    freeKeyExpansion,
    allocateBlock,
    freeBlock
};

CryptoTest::BlockCipher::TypeByteInterface<KeyExpansion_t, Block_t> byteInterface{
    [](const KeyExpansion_t*const input, size_t keySize,const uint8_t* bytes) -> bool{
        return compareKeyExpansionBytes(input, bytes);
    },
    [](KeyExpansion_t*const output, size_t keySize, const unsigned char*const input) -> int{
        if(keySize != 128 && keySize != 192 && keySize != 256) return 1;
        return static_cast<int>(KeyExpansionReadFromBytes(output, input));
    },
    [](const Block_t*const input, const uint8_t* bytes) -> bool{
        return compareBlockBytes(input, bytes);
    },
    [](Block_t*const output, const unsigned char*const input) -> int {
        return static_cast<int>(BlockFromBytes(output, input));
    }
};

CryptoTest::BlockCipher::Tester<KeyExpansion_t, Block_t> tester{
    byteInterface,
    callbacks
};

static auto keyExpansionBuilder = [](const unsigned char* key, size_t keySize, KeyExpansion_t* ke) -> int {
    return KeyExpansionInit(ke, key, keySize, false);
};

static auto encryptor = [](const Block_t*const input, const KeyExpansion_t*const ke, Block_t* output) -> int {
    return encryptBlock(input, ke, output, false);
};

static auto decryptor = [](const Block_t*const input, const KeyExpansion_t*const ke, Block_t* output) -> int {
    return decryptBlock(input, ke, output, false);
};

TEST(AESBlockCipher, AES128) {
    ASSERT_TRUE(tester.validateInfrastructure());
    EXPECT_TRUE(tester.runTestSuite(
        TestVectors::AES::KeySize::AES128,
        keyExpansionBuilder, encryptor, decryptor
    ));
}

TEST(AESBlockCipher, AES192) {
    EXPECT_TRUE(tester.runTestSuite(
        TestVectors::AES::KeySize::AES192,
        keyExpansionBuilder, encryptor, decryptor
    ));
}

TEST(AESBlockCipher, AES256) {
    EXPECT_TRUE(tester.runTestSuite(
        TestVectors::AES::KeySize::AES256,
        keyExpansionBuilder, encryptor, decryptor
    ));
}
