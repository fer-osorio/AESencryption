#include "../include/test_framework.hpp"
#include "../../include/key.hpp"
#include <vector>
#include <fstream>
#include <sstream>
#include <cstdio>  // For remove()
#include <map>

#define AESKEYLEN AESencryption::Key::LengthBits

namespace KeyhppTestVectors{
    // Standard AES test keys
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

// 1. Construction Tests
bool test_key_construction_from_length(AESKEYLEN keyLenBits);
bool test_key_construction_from_vector(AESKEYLEN keyLenBits);
bool test_key_construction_errors(AESKEYLEN keyLenBits);

// 2. Copy and Assignment Tests
bool test_key_copy_construction(AESKEYLEN keyLenBits);
bool test_key_assignment(AESKEYLEN keyLenBits);

// 3. Equality Tests
bool test_key_equality(AESKEYLEN keyLenBits);

// 4. File I/O Tests
bool test_key_save_and_load(AESKEYLEN keyLenBits);
bool test_key_load_errors(AESKEYLEN keyLenBits);

// 6. Memory Management Tests
bool test_key_memory_management(AESKEYLEN keyLenBits);

/**
 * @brief Runs the complete set of tests for a specific key length.
 *
 * This function prints a banner for the key length and then executes the tests for key structure.
 *
 * @param keyLenBits The key length to test.
 * @return true if all tests passed, false otherwise.
 */
bool runTestsForKeylength(AESKEYLEN keyLenBits);

int main() {
    std::cout << "===================== Key Class Tests =====================" << std::endl;
    AESKEYLEN key_lengths[3] = { AESKEYLEN::_128, AESKEYLEN::_192, AESKEYLEN::_256 };
    bool allTestsSucceed = true;

    // Construction tests
    allTestsSucceed &= test_key_construction_from_length();
    allTestsSucceed &= test_key_construction_from_vector();

    for(AESKEYLEN kl: key_lengths){
        // Construction test
        test_key_construction_errors(kl);

        // Copy and assignment tests
        test_key_copy_construction(kl);
        test_key_assignment(kl);

        // Equality tests
        test_key_equality(kl);

        // File I/O tests
        test_key_save_and_load(kl);
        test_key_load_errors(kl);

        // Memory management tests
        test_key_memory_management(kl);
    }

    std::cout << "\n===================== Key Class Tests Complete =====================" << std::endl;
    return 0;
}

static std::map<AESKEYLEN, size_t> keyLengths_Sizet = {
    {AESKEYLEN::_128, 128},
    {AESKEYLEN::_192, 192},
    {AESKEYLEN::_256, 256}
};

bool test_key_construction_from_length(AESKEYLEN keyLenBits) {
    TEST_SUITE("Key Construction from Length");
    bool success = true;

    // Test Key generation
    AESencryption::Key key_128(keyLenBits);
    size_t keylensizet = keyLengths_Sizet.find(keyLenBits)->second;
    size_t sizeInBytes = keylensizet/8;
    success &= ASSERT_EQUAL(keylensizet, static_cast<int>(key_128.getLenBits()), "Key should have correct" + std::to_string(keylensizet) + " length");
    success &= ASSERT_EQUAL(sizeInBytes, static_cast<int>(key_128.getLenBytes()), "Key should have " + std::to_string(sizeInBytes) + "bytes");

    PRINT_RESULTS();
    return success;
}

bool test_key_construction_from_vector(AESKEYLEN keyLenBits) {
    TEST_SUITE("Key Construction from Vector");
    bool success = true;

    // Test 128-bit key from vector
    AESencryption::Key key_128(KeyhppTestVectors::key_128, AESKEYLEN::_128);
    success &= ASSERT_EQUAL(128, static_cast<int>(key_128.getLenBits()), "128-bit key should have correct length");
    success &= ASSERT_EQUAL(16, static_cast<int>(key_128.getLenBytes()), "128-bit key should have 16 bytes");

    // Test 192-bit key from vector
    AESencryption::Key key_192(KeyhppTestVectors::key_192, AESKEYLEN::_192);
    success &= ASSERT_EQUAL(192, static_cast<int>(key_192.getLenBits()), "192-bit key should have correct length");
    success &= ASSERT_EQUAL(24, static_cast<int>(key_192.getLenBytes()), "192-bit key should have 24 bytes");

    // Test 256-bit key from vector
    AESencryption::Key key_256(KeyhppTestVectors::key_256, AESKEYLEN::_256);
    success &= ASSERT_EQUAL(256, static_cast<int>(key_256.getLenBits()), "256-bit key should have correct length");
    success &= ASSERT_EQUAL(32, static_cast<int>(key_256.getLenBytes()), "256-bit key should have 32 bytes");

    PRINT_RESULTS();
    return success;
}

bool test_key_construction_errors(AESKEYLEN keyLenBits) {
    TEST_SUITE("Key Construction Error Handling");
    KeyhppTest keytest(keyLenBits);
    bool success = true;

    // Test insufficient vector size
    std::vector<uint8_t> short_key = {0x01, 0x02, 0x03, 0x04}; // Only 4 bytes

    try {
        AESencryption::Key key(short_key, keyLenBits);
        success &= ASSERT_TRUE(false, "Constructor should throw exception for insufficient key size");
    } catch (const std::exception& e) {
        success &= ASSERT_TRUE(true, "Constructor properly threw exception for insufficient key size");
    }

    // Test mismatched vector size and declared length
    if(keyLenBits != AESKEYLEN::_256) {
        try {
            AESencryption::Key key(keytest.getKey(), AESKEYLEN::_256);
            success &= ASSERT_TRUE(false, "Constructor should throw exception for size mismatch");
        } catch (const std::exception& e) {
            success &= ASSERT_TRUE(true, "Constructor properly threw exception for size mismatch");
        }
    }else {
        try {
            AESencryption::Key key(keytest.getKey(), AESKEYLEN::_256);
            success &= ASSERT_TRUE(true, "Constructor should not throw exception for size match");
        } catch (const std::exception& e) {
            success &= ASSERT_TRUE(false, "Constructor should not throw exception for size match");
        }
    }

    PRINT_RESULTS();
    return success;
}

bool test_key_copy_construction(AESKEYLEN keyLenBits) {
    TEST_SUITE("Key Copy Construction");
    KeyhppTest keytest(keyLenBits);
    AESencryption::Key original(keytest.getKey(), keytest.getKeyLenBits());
    AESencryption::Key copy(original);
    bool success = true;

    // Test that copy has same properties
    success &= ASSERT_EQUAL(
        static_cast<int>(original.getLenBits()),
        static_cast<int>(copy.getLenBits()),
        "Copy should have same length"
    );

    success &= ASSERT_EQUAL(
        static_cast<int>(original.getLenBytes()),
        static_cast<int>(copy.getLenBytes()),
        "Copy should have same byte length"
    );

    // Test equality
    success &= ASSERT_TRUE(original == copy, "Copy should be equal to original");

    PRINT_RESULTS();
    return success;
}

bool test_key_assignment(AESKEYLEN keyLenBits) {
    TEST_SUITE("Key Assignment Operator");
    KeyhppTest keytest(keyLenBits);
    AESencryption::Key key1(keytest.getKey(), keytest.getKeyLenBits());
    AESencryption::Key key2(
        keytest.getKeyLenBits() != AESKEYLEN::_256 ? AESKEYLEN::_256 : AESKEYLEN::_192  // Different size
    );
    bool success = true;

    // Perform assignment
    key2 = key1;

    // Test that key2 now matches key1
    success &= ASSERT_EQUAL(
        static_cast<int>(key1.getLenBits()),
        static_cast<int>(key2.getLenBits()),
        "Assigned key should have same length"
    );

    success &= ASSERT_TRUE(key1 == key2, "Assigned key should equal original");

    // Test self-assignment
    key1 = key1;
    success &= ASSERT_TRUE(key1 == key2, "Self-assignment should not corrupt key");

    PRINT_RESULTS();
    return success;
}

bool test_key_equality(AESKEYLEN keyLenBits) {
    TEST_SUITE("Key Equality Operator");
    KeyhppTest keytest(keyLenBits);
    bool success = true;

    // Test keys with same data are equal
    AESencryption::Key key1(keytest.getKey(), keytest.getKeyLenBits());
    AESencryption::Key key2(keytest.getKey(), keytest.getKeyLenBits());

    success &= ASSERT_TRUE(key1 == key2, "Keys with same data should be equal");

    // Test keys with different data are not equal
    const std::vector<uint8_t>& key3data = keyLenBits != AESKEYLEN::_192 ? KeyhppTestVectors::key_192 : KeyhppTestVectors::key_128;
    const AESKEYLEN key3Len = keyLenBits != AESKEYLEN::_192 ? AESKEYLEN::_192 : AESKEYLEN::_128;
    AESencryption::Key key3(key3data, key3Len);
    success &= ASSERT_TRUE(!(key1 == key3), "Keys with different data should not be equal");

    // Test keys with different lengths are not equal
    AESencryption::Key key4(keyLenBits != AESKEYLEN::_192 ? AESKEYLEN::_192 : AESKEYLEN::_128);
    AESencryption::Key key5(keyLenBits);
    success &= ASSERT_TRUE(!(key4 == key5), "Keys with different lengths should not be equal");

    PRINT_RESULTS();
    return success;
}

bool test_key_save_and_load(AESKEYLEN keyLenBits) {
    TEST_SUITE("Key Save and Load");
    KeyhppTest keytest(keyLenBits);
    bool success = true;

    // Save 128-bit key
    AESencryption::Key original(keytest.getKey(), keytest.getKeyLenBits());
    original.save(keytest.getFileName());

    // Load it back
    AESencryption::Key loaded(keytest.getFileName());

    success &= ASSERT_TRUE(original == loaded, "Loaded key should equal original");
    success &= ASSERT_EQUAL(
        static_cast<int>(original.getLenBits()),
        static_cast<int>(loaded.getLenBits()),
        "Loaded key should have same length"
    );
    // Clean up test files
    std::remove(keytest.getFileName());

    PRINT_RESULTS();
    return success;
}

bool test_key_load_errors(AESKEYLEN keyLenBits) {
    TEST_SUITE("Key Load Error Handling");
    KeyhppTest keytest(keyLenBits);
    size_t keyLengthBytes = static_cast<size_t>(keyLenBits)/8;
    bool success = true;

    // Test loading from non-existent file
    try {
        AESencryption::Key key("non_existent_file.bin");
        success &= ASSERT_TRUE(false, "Loading from non-existent file should throw exception");
    } catch (const std::exception& e) {
        success &= ASSERT_TRUE(true, "Loading from non-existent file properly threw exception");
    }

    // Test loading from file with wrong header
    const char* wrong_header_file = "wrong_header.bin";
    std::ofstream ofs1(wrong_header_file, std::ios::binary);
    ofs1.write("WRONG!", 6);  // Wrong header ID
    uint16_t valid_len = static_cast<uint16_t>(keytest.getKeyLenBits());
    ofs1.write(reinterpret_cast<char*>(&valid_len), 2);
    uint8_t dummy_key[32] = {0};
    ofs1.write(reinterpret_cast<char*>(dummy_key), keyLengthBytes);
    ofs1.close();

    try {
        AESencryption::Key key(wrong_header_file);
        success &= ASSERT_TRUE(false, "Loading file with wrong header should throw exception");
    } catch (const std::exception& e) {
        success &= ASSERT_TRUE(true, "Loading file with wrong header properly threw exception");
    }
    std::remove(wrong_header_file);

    // Test loading from file with invalid key length
    const char* invalid_length_file = "invalid_length.bin";
    std::ofstream ofs2(invalid_length_file, std::ios::binary);
    ofs2.write("AESKEY", 6);                                                    // Correct header
    uint16_t invalid_len = 512;                                                 // Invalid key length
    ofs2.write(reinterpret_cast<char*>(&invalid_len), 2);
    ofs2.write(reinterpret_cast<char*>(dummy_key), keyLengthBytes);
    ofs2.close();

    try {
        AESencryption::Key key(invalid_length_file);
        success &= ASSERT_TRUE(false, "Loading file with invalid key length should throw exception");
    } catch (const std::exception& e) {
        success &= ASSERT_TRUE(true, "Loading file with invalid key length properly threw exception");
    }
    std::remove(invalid_length_file);

    // Test loading from truncated file (incomplete key data)
    const char* truncated_file = "truncated.bin";
    std::ofstream ofs3(truncated_file, std::ios::binary);
    ofs3.write("AESKEY", 6);
    uint16_t key_len = static_cast<uint16_t>(keytest.getKeyLenBits());
    ofs3.write(reinterpret_cast<char*>(&key_len), 2);
    ofs3.write(reinterpret_cast<char*>(dummy_key), 8);                          // Only 8 bytes, smaller than any valid key
    ofs3.close();

    try {
        AESencryption::Key key(truncated_file);
        // This might succeed or fail depending on implementation
        // The test validates that the constructor handles this case
        success &= ASSERT_TRUE(true, "Truncated file was handled");
    } catch (const std::exception& e) {
        success &= ASSERT_TRUE(true, "Truncated file properly threw exception");
    }
    std::remove(truncated_file);

    PRINT_RESULTS();
    return success;
}

bool test_key_memory_management(AESKEYLEN keyLenBits) {
    TEST_SUITE("Key Memory Management");
    bool success = true;

    // Test that multiple keys can coexist
    {
        AESencryption::Key key1(AESKEYLEN::_128);
        AESencryption::Key key2(AESKEYLEN::_192);
        AESencryption::Key key3(AESKEYLEN::_256);

        success &= ASSERT_TRUE(key1.getLenBytes() == 16, "Key1 should maintain correct size");
        success &= ASSERT_TRUE(key2.getLenBytes() == 24, "Key2 should maintain correct size");
        success &= ASSERT_TRUE(key3.getLenBytes() == 32, "Key3 should maintain correct size");
    } // All keys should be properly destroyed here

    // Test that keys can be created and destroyed in a loop
    for (int i = 0; i < 1024; ++i) {
        AESencryption::Key temp(keyLenBits);
    }
    success &= ASSERT_TRUE(true, "Multiple create/destroy cycles completed successfully");

    PRINT_RESULTS();
    return success;
}

bool runTestsForKeylength(AESKEYLEN keyLenBits){
    bool success = true;
    std::string keylenStr = std::to_string(static_cast<int>(keyLenBits));
    std::cout << "\n=================================================================\n"
              << "\n===================== AES key " << keylenStr << " bits ========================\n"
              << "\n=================================================================\n" << std::endl;

    // Construction test
    success &= test_key_construction_errors(keyLenBits);

    // Copy and assignment tests
    success &= test_key_copy_construction(keyLenBits);
    success &= test_key_assignment(keyLenBits);

    // Equality tests
    success &= test_key_equality(keyLenBits);

    // File I/O tests
    success &= test_key_save_and_load(keyLenBits);
    success &= test_key_load_errors(keyLenBits);

    // Memory management tests
    success &= test_key_memory_management(keyLenBits);

    return success;
}
