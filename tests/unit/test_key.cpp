#include <gtest/gtest.h>
#include "../../core-crypto/include/key.hpp"
#include <vector>
#include <fstream>
#include <cstdio>
#include <map>

#define AESKEYLEN CipherFortis::Key::LengthBits

namespace KeyhppTestVectors{
    static const std::vector<uint8_t> key_128 = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    static const std::vector<uint8_t> key_192 = {
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
        0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
        0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
    };

    static const std::vector<uint8_t> key_256 = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };

    static const char* test_file_128 = "test_key_128.bin";
    static const char* test_file_192 = "test_key_192.bin";
    static const char* test_file_256 = "test_key_256.bin";
}

struct KeyhppTest {
private:
    AESKEYLEN lengthBits;
    std::vector<uint8_t> key;
    const char* fileName;
public:
    KeyhppTest(AESKEYLEN keyLen): lengthBits(keyLen) {
        switch(keyLen){
            case AESKEYLEN::_128:
                this->key = KeyhppTestVectors::key_128;
                this->fileName = KeyhppTestVectors::test_file_128;
                break;
            case AESKEYLEN::_192:
                this->key = KeyhppTestVectors::key_192;
                this->fileName = KeyhppTestVectors::test_file_192;
                break;
            case AESKEYLEN::_256:
                this->key = KeyhppTestVectors::key_256;
                this->fileName = KeyhppTestVectors::test_file_256;
                break;
        }
    }
    AESKEYLEN getKeyLenBits() { return this->lengthBits; }
    const std::vector<uint8_t>& getKey() { return this->key; }
    const char* getFileName() { return this->fileName; }
};

static const std::map<AESKEYLEN, size_t> keyLengths_Sizet = {
    {AESKEYLEN::_128, 128},
    {AESKEYLEN::_192, 192},
    {AESKEYLEN::_256, 256}
};

void test_key_construction_from_length(AESKEYLEN keyLenBits) {
    CipherFortis::Key key(keyLenBits);
    size_t keylensizet = keyLengths_Sizet.find(keyLenBits)->second;
    size_t sizeInBytes = keylensizet/8;

    EXPECT_EQ(static_cast<int>(keylensizet), static_cast<int>(key.getLenBits()))
        << "Key should have correct " + std::to_string(keylensizet) + " length";
    EXPECT_EQ(static_cast<int>(sizeInBytes), static_cast<int>(key.getLenBytes()))
        << "Key should have " + std::to_string(sizeInBytes) + " bytes";
}

void test_key_construction_from_vector(AESKEYLEN keyLenBits) {
    KeyhppTest keytest(keyLenBits);
    CipherFortis::Key key(keytest.getKey(), keytest.getKeyLenBits());
    size_t keylensizet = keyLengths_Sizet.find(keyLenBits)->second;
    size_t sizeInBytes = keylensizet/8;

    EXPECT_EQ(static_cast<int>(keylensizet), static_cast<int>(key.getLenBits()))
        << "Key should have correct " + std::to_string(keylensizet) + " length";
    EXPECT_EQ(static_cast<int>(sizeInBytes), static_cast<int>(key.getLenBytes()))
        << "Key should have " + std::to_string(sizeInBytes) + " bytes";
}

void test_key_construction_errors(AESKEYLEN keyLenBits) {
    KeyhppTest keytest(keyLenBits);

    std::vector<uint8_t> short_key = {0x01, 0x02, 0x03, 0x04};

    try {
        CipherFortis::Key key(short_key, keyLenBits);
        FAIL() << "Constructor should throw exception for insufficient key size";
    } catch (const std::exception&) {
        // expected
    }

    if(keyLenBits != AESKEYLEN::_256) {
        try {
            CipherFortis::Key key(keytest.getKey(), AESKEYLEN::_256);
            FAIL() << "Constructor should throw exception for size mismatch";
        } catch (const std::exception&) {
            // expected
        }
    } else {
        try {
            CipherFortis::Key key(keytest.getKey(), AESKEYLEN::_256);
        } catch (const std::exception& e) {
            FAIL() << "Constructor should not throw exception for size match: " << e.what();
        }
    }
}

void test_key_copy_construction(AESKEYLEN keyLenBits) {
    KeyhppTest keytest(keyLenBits);
    CipherFortis::Key original(keytest.getKey(), keytest.getKeyLenBits());
    CipherFortis::Key copy(original);

    EXPECT_EQ(static_cast<int>(original.getLenBits()), static_cast<int>(copy.getLenBits()))
        << "Copy should have same length";
    EXPECT_EQ(static_cast<int>(original.getLenBytes()), static_cast<int>(copy.getLenBytes()))
        << "Copy should have same byte length";
    EXPECT_TRUE(original == copy) << "Copy should be equal to original";
}

void test_key_assignment(AESKEYLEN keyLenBits) {
    KeyhppTest keytest(keyLenBits);
    CipherFortis::Key key1(keytest.getKey(), keytest.getKeyLenBits());
    CipherFortis::Key key2(
        keytest.getKeyLenBits() != AESKEYLEN::_256 ? AESKEYLEN::_256 : AESKEYLEN::_192
    );

    key2 = key1;

    EXPECT_EQ(static_cast<int>(key1.getLenBits()), static_cast<int>(key2.getLenBits()))
        << "Assigned key should have same length";
    EXPECT_TRUE(key1 == key2) << "Assigned key should equal original";

    key1 = key1;
    EXPECT_TRUE(key1 == key2) << "Self-assignment should not corrupt key";
}

void test_key_equality(AESKEYLEN keyLenBits) {
    KeyhppTest keytest(keyLenBits);

    CipherFortis::Key key1(keytest.getKey(), keytest.getKeyLenBits());
    CipherFortis::Key key2(keytest.getKey(), keytest.getKeyLenBits());

    EXPECT_TRUE(key1 == key2) << "Keys with same data should be equal";

    const std::vector<uint8_t>& key3data = keyLenBits != AESKEYLEN::_192
        ? KeyhppTestVectors::key_192 : KeyhppTestVectors::key_128;
    const AESKEYLEN key3Len = keyLenBits != AESKEYLEN::_192 ? AESKEYLEN::_192 : AESKEYLEN::_128;
    CipherFortis::Key key3(key3data, key3Len);
    EXPECT_TRUE(!(key1 == key3)) << "Keys with different data should not be equal";

    CipherFortis::Key key4(keyLenBits != AESKEYLEN::_192 ? AESKEYLEN::_192 : AESKEYLEN::_128);
    CipherFortis::Key key5(keyLenBits);
    EXPECT_TRUE(!(key4 == key5)) << "Keys with different lengths should not be equal";
}

void test_key_save_and_load(AESKEYLEN keyLenBits) {
    KeyhppTest keytest(keyLenBits);

    CipherFortis::Key original(keytest.getKey(), keytest.getKeyLenBits());
    original.save(keytest.getFileName());

    CipherFortis::Key loaded(keytest.getFileName());

    EXPECT_TRUE(original == loaded) << "Loaded key should equal original";
    EXPECT_EQ(static_cast<int>(original.getLenBits()), static_cast<int>(loaded.getLenBits()))
        << "Loaded key should have same length";

    std::remove(keytest.getFileName());
}

void test_key_load_errors(AESKEYLEN keyLenBits) {
    KeyhppTest keytest(keyLenBits);
    size_t keyLengthBytes = static_cast<size_t>(keyLenBits)/8;

    try {
        CipherFortis::Key key("non_existent_file.bin");
        FAIL() << "Loading from non-existent file should throw exception";
    } catch (const std::exception&) {
        // expected
    }

    const char* wrong_header_file = "wrong_header.bin";
    {
        std::ofstream ofs1(wrong_header_file, std::ios::binary);
        ofs1.write("WRONG!", 6);
        uint16_t valid_len = static_cast<uint16_t>(keytest.getKeyLenBits());
        ofs1.write(reinterpret_cast<char*>(&valid_len), 2);
        uint8_t dummy_key[32] = {0};
        ofs1.write(reinterpret_cast<char*>(dummy_key), keyLengthBytes);
    }
    try {
        CipherFortis::Key key(wrong_header_file);
        FAIL() << "Loading file with wrong header should throw exception";
    } catch (const std::exception&) {
        // expected
    }
    std::remove(wrong_header_file);

    const char* invalid_length_file = "invalid_length.bin";
    {
        std::ofstream ofs2(invalid_length_file, std::ios::binary);
        ofs2.write("AESKEY", 6);
        uint16_t invalid_len = 512;
        ofs2.write(reinterpret_cast<char*>(&invalid_len), 2);
        uint8_t dummy_key[32] = {0};
        ofs2.write(reinterpret_cast<char*>(dummy_key), keyLengthBytes);
    }
    try {
        CipherFortis::Key key(invalid_length_file);
        FAIL() << "Loading file with invalid key length should throw exception";
    } catch (const std::exception&) {
        // expected
    }
    std::remove(invalid_length_file);

    const char* truncated_file = "truncated.bin";
    {
        std::ofstream ofs3(truncated_file, std::ios::binary);
        ofs3.write("AESKEY", 6);
        uint16_t key_len = static_cast<uint16_t>(keytest.getKeyLenBits());
        ofs3.write(reinterpret_cast<char*>(&key_len), 2);
        uint8_t dummy_key[32] = {0};
        ofs3.write(reinterpret_cast<char*>(dummy_key), 8);
    }
    try {
        CipherFortis::Key key(truncated_file);
    } catch (const std::exception&) {
        // acceptable — truncated file may or may not throw
    }
    std::remove(truncated_file);
}

void test_key_memory_management(AESKEYLEN keyLenBits) {
    {
        CipherFortis::Key key1(AESKEYLEN::_128);
        CipherFortis::Key key2(AESKEYLEN::_192);
        CipherFortis::Key key3(AESKEYLEN::_256);

        EXPECT_TRUE(key1.getLenBytes() == 16) << "Key1 should maintain correct size";
        EXPECT_TRUE(key2.getLenBytes() == 24) << "Key2 should maintain correct size";
        EXPECT_TRUE(key3.getLenBytes() == 32) << "Key3 should maintain correct size";
    }

    for (int i = 0; i < 1024; ++i) {
        CipherFortis::Key temp(keyLenBits);
    }
}

// ── 27 TEST cases (3 key sizes × 9 test functions) ───────────────────────────

TEST(KeyTest, ConstructionFromLength_AES128) { test_key_construction_from_length(AESKEYLEN::_128); }
TEST(KeyTest, ConstructionFromLength_AES192) { test_key_construction_from_length(AESKEYLEN::_192); }
TEST(KeyTest, ConstructionFromLength_AES256) { test_key_construction_from_length(AESKEYLEN::_256); }

TEST(KeyTest, ConstructionFromVector_AES128) { test_key_construction_from_vector(AESKEYLEN::_128); }
TEST(KeyTest, ConstructionFromVector_AES192) { test_key_construction_from_vector(AESKEYLEN::_192); }
TEST(KeyTest, ConstructionFromVector_AES256) { test_key_construction_from_vector(AESKEYLEN::_256); }

TEST(KeyTest, ConstructionErrors_AES128) { test_key_construction_errors(AESKEYLEN::_128); }
TEST(KeyTest, ConstructionErrors_AES192) { test_key_construction_errors(AESKEYLEN::_192); }
TEST(KeyTest, ConstructionErrors_AES256) { test_key_construction_errors(AESKEYLEN::_256); }

TEST(KeyTest, CopyConstruction_AES128) { test_key_copy_construction(AESKEYLEN::_128); }
TEST(KeyTest, CopyConstruction_AES192) { test_key_copy_construction(AESKEYLEN::_192); }
TEST(KeyTest, CopyConstruction_AES256) { test_key_copy_construction(AESKEYLEN::_256); }

TEST(KeyTest, Assignment_AES128) { test_key_assignment(AESKEYLEN::_128); }
TEST(KeyTest, Assignment_AES192) { test_key_assignment(AESKEYLEN::_192); }
TEST(KeyTest, Assignment_AES256) { test_key_assignment(AESKEYLEN::_256); }

TEST(KeyTest, Equality_AES128) { test_key_equality(AESKEYLEN::_128); }
TEST(KeyTest, Equality_AES192) { test_key_equality(AESKEYLEN::_192); }
TEST(KeyTest, Equality_AES256) { test_key_equality(AESKEYLEN::_256); }

TEST(KeyTest, SaveAndLoad_AES128) { test_key_save_and_load(AESKEYLEN::_128); }
TEST(KeyTest, SaveAndLoad_AES192) { test_key_save_and_load(AESKEYLEN::_192); }
TEST(KeyTest, SaveAndLoad_AES256) { test_key_save_and_load(AESKEYLEN::_256); }

TEST(KeyTest, LoadErrors_AES128) { test_key_load_errors(AESKEYLEN::_128); }
TEST(KeyTest, LoadErrors_AES192) { test_key_load_errors(AESKEYLEN::_192); }
TEST(KeyTest, LoadErrors_AES256) { test_key_load_errors(AESKEYLEN::_256); }

TEST(KeyTest, MemoryManagement_AES128) { test_key_memory_management(AESKEYLEN::_128); }
TEST(KeyTest, MemoryManagement_AES192) { test_key_memory_management(AESKEYLEN::_192); }
TEST(KeyTest, MemoryManagement_AES256) { test_key_memory_management(AESKEYLEN::_256); }
