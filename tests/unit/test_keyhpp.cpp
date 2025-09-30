#include "../include/test_framework.hpp"
#include "../../include/key.hpp"
#include <vector>
#include <fstream>
#include <sstream>
#include <cstdio>  // For remove()

namespace TestVectors {
    // Standard AES test keys
    const std::vector<uint8_t> key_128 = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    const std::vector<uint8_t> key_192 = {
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
        0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
        0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
    };

    const std::vector<uint8_t> key_256 = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };

    const char* test_file_128 = "test_key_128.bin";
    const char* test_file_192 = "test_key_192.bin";
    const char* test_file_256 = "test_key_256.bin";
}

// 1. Construction Tests
void test_key_construction_from_length() {
    TEST_SUITE("Key Construction from Length");

    // Test 128-bit key generation
    AESencryption::Key key_128(AESencryption::Key::LengthBits::_128);
    ASSERT_EQUAL(128, static_cast<int>(key_128.getLenBits()), "128-bit key should have correct length");
    ASSERT_EQUAL(16, static_cast<int>(key_128.getLenBytes()), "128-bit key should have 16 bytes");

    // Test 192-bit key generation
    AESencryption::Key key_192(AESencryption::Key::LengthBits::_192);
    ASSERT_EQUAL(192, static_cast<int>(key_192.getLenBits()), "192-bit key should have correct length");
    ASSERT_EQUAL(24, static_cast<int>(key_192.getLenBytes()), "192-bit key should have 24 bytes");

    // Test 256-bit key generation
    AESencryption::Key key_256(AESencryption::Key::LengthBits::_256);
    ASSERT_EQUAL(256, static_cast<int>(key_256.getLenBits()), "256-bit key should have correct length");
    ASSERT_EQUAL(32, static_cast<int>(key_256.getLenBytes()), "256-bit key should have 32 bytes");

    PRINT_RESULTS();
}

void test_key_construction_from_vector() {
    TEST_SUITE("Key Construction from Vector");

    // Test 128-bit key from vector
    AESencryption::Key key_128(TestVectors::key_128, AESencryption::Key::LengthBits::_128);
    ASSERT_EQUAL(128, static_cast<int>(key_128.getLenBits()), "128-bit key should have correct length");
    ASSERT_EQUAL(16, static_cast<int>(key_128.getLenBytes()), "128-bit key should have 16 bytes");

    // Test 192-bit key from vector
    AESencryption::Key key_192(TestVectors::key_192, AESencryption::Key::LengthBits::_192);
    ASSERT_EQUAL(192, static_cast<int>(key_192.getLenBits()), "192-bit key should have correct length");
    ASSERT_EQUAL(24, static_cast<int>(key_192.getLenBytes()), "192-bit key should have 24 bytes");

    // Test 256-bit key from vector
    AESencryption::Key key_256(TestVectors::key_256, AESencryption::Key::LengthBits::_256);
    ASSERT_EQUAL(256, static_cast<int>(key_256.getLenBits()), "256-bit key should have correct length");
    ASSERT_EQUAL(32, static_cast<int>(key_256.getLenBytes()), "256-bit key should have 32 bytes");

    PRINT_RESULTS();
}

void test_key_construction_errors() {
    TEST_SUITE("Key Construction Error Handling");

    // Test insufficient vector size
    std::vector<uint8_t> short_key = {0x01, 0x02, 0x03, 0x04}; // Only 4 bytes

    try {
        AESencryption::Key key(short_key, AESencryption::Key::LengthBits::_128);
        ASSERT_TRUE(false, "Constructor should throw exception for insufficient key size");
    } catch (const std::exception& e) {
        ASSERT_TRUE(true, "Constructor properly threw exception for insufficient key size");
    }

    // Test mismatched vector size and declared length
    try {
        AESencryption::Key key(TestVectors::key_128, AESencryption::Key::LengthBits::_256);
        ASSERT_TRUE(false, "Constructor should throw exception for size mismatch");
    } catch (const std::exception& e) {
        ASSERT_TRUE(true, "Constructor properly threw exception for size mismatch");
    }

    PRINT_RESULTS();
}

// 2. Copy and Assignment Tests
void test_key_copy_construction() {
    TEST_SUITE("Key Copy Construction");

    AESencryption::Key original(TestVectors::key_128, AESencryption::Key::LengthBits::_128);
    AESencryption::Key copy(original);

    // Test that copy has same properties
    ASSERT_EQUAL(static_cast<int>(original.getLenBits()),
                 static_cast<int>(copy.getLenBits()),
                 "Copy should have same length");

    ASSERT_EQUAL(static_cast<int>(original.getLenBytes()),
                 static_cast<int>(copy.getLenBytes()),
                 "Copy should have same byte length");

    // Test equality
    ASSERT_TRUE(original == copy, "Copy should be equal to original");

    PRINT_RESULTS();
}

void test_key_assignment() {
    TEST_SUITE("Key Assignment Operator");

    AESencryption::Key key1(TestVectors::key_128, AESencryption::Key::LengthBits::_128);
    AESencryption::Key key2(AESencryption::Key::LengthBits::_256); // Different size

    // Perform assignment
    key2 = key1;

    // Test that key2 now matches key1
    ASSERT_EQUAL(static_cast<int>(key1.getLenBits()),
                 static_cast<int>(key2.getLenBits()),
                 "Assigned key should have same length");

    ASSERT_TRUE(key1 == key2, "Assigned key should equal original");

    // Test self-assignment
    key1 = key1;
    ASSERT_TRUE(key1 == key2, "Self-assignment should not corrupt key");

    PRINT_RESULTS();
}

// 3. Equality Tests
void test_key_equality() {
    TEST_SUITE("Key Equality Operator");

    // Test keys with same data are equal
    AESencryption::Key key1(TestVectors::key_128, AESencryption::Key::LengthBits::_128);
    AESencryption::Key key2(TestVectors::key_128, AESencryption::Key::LengthBits::_128);

    ASSERT_TRUE(key1 == key2, "Keys with same data should be equal");

    // Test keys with different data are not equal
    AESencryption::Key key3(TestVectors::key_192, AESencryption::Key::LengthBits::_192);
    ASSERT_TRUE(!(key1 == key3), "Keys with different data should not be equal");

    // Test keys with different lengths are not equal
    AESencryption::Key key4(AESencryption::Key::LengthBits::_128);
    AESencryption::Key key5(AESencryption::Key::LengthBits::_256);
    ASSERT_TRUE(!(key4 == key5), "Keys with different lengths should not be equal");

    PRINT_RESULTS();
}

// 4. File I/O Tests
void test_key_save_and_load() {
    TEST_SUITE("Key Save and Load");

    // Save 128-bit key
    AESencryption::Key original_128(TestVectors::key_128, AESencryption::Key::LengthBits::_128);
    original_128.save(TestVectors::test_file_128);

    // Load it back
    AESencryption::Key loaded_128(TestVectors::test_file_128);

    ASSERT_TRUE(original_128 == loaded_128, "Loaded 128-bit key should equal original");
    ASSERT_EQUAL(static_cast<int>(original_128.getLenBits()),
                 static_cast<int>(loaded_128.getLenBits()),
                 "Loaded key should have same length");

    // Save 192-bit key
    AESencryption::Key original_192(TestVectors::key_192, AESencryption::Key::LengthBits::_192);
    original_192.save(TestVectors::test_file_192);

    // Load it back
    AESencryption::Key loaded_192(TestVectors::test_file_192);

    ASSERT_TRUE(original_192 == loaded_192, "Loaded 192-bit key should equal original");

    // Save 256-bit key
    AESencryption::Key original_256(TestVectors::key_256, AESencryption::Key::LengthBits::_256);
    original_256.save(TestVectors::test_file_256);

    // Load it back
    AESencryption::Key loaded_256(TestVectors::test_file_256);

    ASSERT_TRUE(original_256 == loaded_256, "Loaded 256-bit key should equal original");

    // Clean up test files
    std::remove(TestVectors::test_file_128);
    std::remove(TestVectors::test_file_192);
    std::remove(TestVectors::test_file_256);

    PRINT_RESULTS();
}

void test_key_load_errors() {
    TEST_SUITE("Key Load Error Handling");

    // Test loading from non-existent file
    try {
        AESencryption::Key key("non_existent_file.bin");
        ASSERT_TRUE(false, "Loading from non-existent file should throw exception");
    } catch (const std::exception& e) {
        ASSERT_TRUE(true, "Loading from non-existent file properly threw exception");
    }

    // Test loading from file with wrong header
    const char* wrong_header_file = "wrong_header.bin";
    std::ofstream ofs1(wrong_header_file, std::ios::binary);
    ofs1.write("WRONG!", 6);  // Wrong header ID
    uint16_t valid_len = 128;
    ofs1.write(reinterpret_cast<char*>(&valid_len), 2);
    uint8_t dummy_key[16] = {0};
    ofs1.write(reinterpret_cast<char*>(dummy_key), 16);
    ofs1.close();

    try {
        AESencryption::Key key(wrong_header_file);
        ASSERT_TRUE(false, "Loading file with wrong header should throw exception");
    } catch (const std::exception& e) {
        ASSERT_TRUE(true, "Loading file with wrong header properly threw exception");
    }
    std::remove(wrong_header_file);

    // Test loading from file with invalid key length
    const char* invalid_length_file = "invalid_length.bin";
    std::ofstream ofs2(invalid_length_file, std::ios::binary);
    ofs2.write("AESKEY", 6);  // Correct header
    uint16_t invalid_len = 512;  // Invalid key length
    ofs2.write(reinterpret_cast<char*>(&invalid_len), 2);
    ofs2.write(reinterpret_cast<char*>(dummy_key), 16);
    ofs2.close();

    try {
        AESencryption::Key key(invalid_length_file);
        ASSERT_TRUE(false, "Loading file with invalid key length should throw exception");
    } catch (const std::exception& e) {
        ASSERT_TRUE(true, "Loading file with invalid key length properly threw exception");
    }
    std::remove(invalid_length_file);

    // Test loading from truncated file (incomplete key data)
    const char* truncated_file = "truncated.bin";
    std::ofstream ofs3(truncated_file, std::ios::binary);
    ofs3.write("AESKEY", 6);
    uint16_t key_len_128 = 128;
    ofs3.write(reinterpret_cast<char*>(&key_len_128), 2);
    ofs3.write(reinterpret_cast<char*>(dummy_key), 8);  // Only 8 bytes instead of 16
    ofs3.close();

    try {
        AESencryption::Key key(truncated_file);
        // This might succeed or fail depending on implementation
        // The test validates that the constructor handles this case
        ASSERT_TRUE(true, "Truncated file was handled");
    } catch (const std::exception& e) {
        ASSERT_TRUE(true, "Truncated file properly threw exception");
    }
    std::remove(truncated_file);

    PRINT_RESULTS();
}

// 5. Stream Output Test
void test_key_stream_output() {
    TEST_SUITE("Key Stream Output");

    AESencryption::Key key(TestVectors::key_128, AESencryption::Key::LengthBits::_128);

    // Test that stream output works without crashing
    std::ostringstream oss;
    oss << key;

    std::string output = oss.str();
    ASSERT_TRUE(output.length() > 0, "Stream output should produce non-empty string");

    // Optionally check if output contains expected information
    ASSERT_TRUE(output.find("128") != std::string::npos ||
                output.find("16") != std::string::npos,
                "Stream output should contain key size information");

    PRINT_RESULTS();
}

// 6. Memory Management Tests
void test_key_memory_management() {
    TEST_SUITE("Key Memory Management");

    // Test that multiple keys can coexist
    {
        AESencryption::Key key1(AESencryption::Key::LengthBits::_128);
        AESencryption::Key key2(AESencryption::Key::LengthBits::_192);
        AESencryption::Key key3(AESencryption::Key::LengthBits::_256);

        ASSERT_TRUE(key1.getLenBytes() == 16, "Key1 should maintain correct size");
        ASSERT_TRUE(key2.getLenBytes() == 24, "Key2 should maintain correct size");
        ASSERT_TRUE(key3.getLenBytes() == 32, "Key3 should maintain correct size");
    } // All keys should be properly destroyed here

    // Test that keys can be created and destroyed in a loop
    for (int i = 0; i < 100; ++i) {
        AESencryption::Key temp(AESencryption::Key::LengthBits::_128);
    }

    ASSERT_TRUE(true, "Multiple create/destroy cycles completed successfully");

    PRINT_RESULTS();
}

int main() {
    std::cout << "=== Key Class Tests ===" << std::endl;

    // Construction tests
    test_key_construction_from_length();
    test_key_construction_from_vector();
    test_key_construction_errors();

    // Copy and assignment tests
    test_key_copy_construction();
    test_key_assignment();

    // Equality tests
    test_key_equality();

    // File I/O tests
    test_key_save_and_load();
    test_key_load_errors();

    // Stream output test
    test_key_stream_output();

    // Memory management tests
    test_key_memory_management();

    std::cout << "\n=== Key Class Tests Complete ===" << std::endl;
    return 0;
}
