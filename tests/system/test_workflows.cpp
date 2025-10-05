// System/E2E Testing Examples for AES File Encryption Tool
// File: system/test_file_encryption_workflows.cpp

#include "../include/test_framework.hpp"
#include "test_workflows.hpp"
#include <filesystem>
#include <fstream>
#include <cstdlib>
#include <string>

// Helper function to execute command line tool
int CommandLineToolsTest::SystemUtils::execute_cli_command(const std::string& command) {
    return std::system(command.c_str());
}

// Helper to create test files
void CommandLineToolsTest::SystemUtils::create_test_file(const std::string& filename, const std::string& content) {
    std::ofstream file(filename);
    file << content;
    file.close();
}

// Helper to read file content
std::string CommandLineToolsTest::SystemUtils::read_file_content(const std::string& filename) {
    std::ifstream file(filename);
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    return content;
}

// Helper to create test bitmap
void CommandLineToolsTest::SystemUtils::create_test_bitmap(const std::string& filename, size_t width, size_t height) {
    // Create a simple test bitmap file
    std::ofstream file(filename, std::ios::binary);

    // BMP header (simplified)
    uint32_t file_size = 54 + (width * height * 3);
    file.write("BM", 2);  // Signature
    file.write(reinterpret_cast<const char*>(&file_size), 4);
    uint32_t reserved = 0;
    file.write(reinterpret_cast<const char*>(&reserved), 4);
    uint32_t offset = 54;
    file.write(reinterpret_cast<const char*>(&offset), 4);

    // Fill with test pattern
    for (size_t i = 0; i < width * height; ++i) {
        uint8_t pixel[3] = {static_cast<uint8_t>(i % 256),
                           static_cast<uint8_t>((i * 2) % 256),
                           static_cast<uint8_t>((i * 3) % 256)};
        file.write(reinterpret_cast<const char*>(pixel), 3);
    }
}


// SYSTEM TEST 1: Complete Text File Encryption Workflow
bool CommandLineToolsTest::SystemTests::test_text_file_encryption_workflow() {
    TEST_SUITE("Text File Encryption E2E Workflow");
    bool success = true;

    // Setup: Create test environment
    const std::string test_dir = "./test_temp/";
    std::filesystem::create_directories(test_dir);

    const std::string original_file = test_dir + "original.txt";
    const std::string encrypted_file = test_dir + "encrypted.aes";
    const std::string decrypted_file = test_dir + "decrypted.txt";
    const std::string key_file = test_dir + "test.key";

    // Test data
    const std::string test_content =
        "This is a test file for AES encryption.\n"
        "It contains multiple lines of text.\n"
        "Special characters: !@#$%^&*()_+{}|:<>?\n"
        "Numbers: 1234567890\n";

    // Step 1: Create original file
    SystemUtils::create_test_file(original_file, test_content);

    // Step 2: Generate encryption key
    std::string gen_key_cmd = this->executable_path + " --generate-key --key-size 256 --output " + key_file;
    int result1 = SystemUtils::execute_cli_command(gen_key_cmd);
    success &= ASSERT_TRUE(result1 == 0, "Key generation should succeed");
    success &= ASSERT_TRUE(std::filesystem::exists(key_file), "Key file should be created");

    // Step 3: Encrypt the file
    std::string encrypt_cmd =
        this->executable_path + " --encrypt --mode CBC --key " + key_file + " --input " + original_file + " --output " + encrypted_file;
    int result2 = SystemUtils::execute_cli_command(encrypt_cmd);
    success &= ASSERT_TRUE(result2 == 0, "File encryption should succeed");
    success &= ASSERT_TRUE(std::filesystem::exists(encrypted_file), "Encrypted file should be created");

    // Step 4: Verify encrypted file is different from original
    std::string encrypted_content = SystemUtils::read_file_content(encrypted_file);
    success &= ASSERT_TRUE(encrypted_content != test_content, "Encrypted content should differ from original");

    // Step 5: Decrypt the file
    std::string decrypt_cmd
        = this->executable_path + " --decrypt --mode CBC --key " + key_file + " --input " + encrypted_file + " --output " + decrypted_file;
    int result3 = SystemUtils::execute_cli_command(decrypt_cmd);
    success &= ASSERT_TRUE(result3 == 0, "File decryption should succeed");
    success &= ASSERT_TRUE(std::filesystem::exists(decrypted_file), "Decrypted file should be created");

    // Step 6: Verify decrypted content matches original
    std::string decrypted_content = SystemUtils::read_file_content(decrypted_file);
    success &= ASSERT_TRUE(decrypted_content == test_content, "Decrypted content should match original");

    // Cleanup
    std::filesystem::remove_all(test_dir);

    PRINT_RESULTS();
    return success;
}

// SYSTEM TEST 2: Image File Encryption Workflow
bool CommandLineToolsTest::SystemTests::test_image_encryption_workflow() {
    TEST_SUITE("Image File Encryption E2E Workflow");
    bool success = true;

    const std::string test_dir = "./test_images/";
    std::filesystem::create_directories(test_dir);

    const std::string original_image = test_dir + "test.bmp";
    const std::string encrypted_image = test_dir + "test_encrypted.bmp";
    const std::string decrypted_image = test_dir + "test_decrypted.bmp";
    const std::string key_file = test_dir + "image.key";

    // Create test bitmap
    SystemUtils::create_test_bitmap(original_image, 100, 100);

    // Generate key
    std::string gen_key_cmd = this->executable_path + " --generate-key --key-size 128 --output " + key_file;
    success &= ASSERT_TRUE(SystemUtils::execute_cli_command(gen_key_cmd) == 0, "Key generation should succeed");

    // Encrypt image
    std::string encrypt_cmd = this->executable_path + " --encrypt --mode ECB --key " + key_file +
                             " --input " + original_image + " --output " + encrypted_image + " --type bitmap";
    success &= ASSERT_TRUE(SystemUtils::execute_cli_command(encrypt_cmd) == 0, "Image encryption should succeed");

    // Decrypt image
    std::string decrypt_cmd = this->executable_path + " --decrypt --mode ECB --key " + key_file +
                             " --input " + encrypted_image + " --output " + decrypted_image + " --type bitmap";
    success &= ASSERT_TRUE(SystemUtils::execute_cli_command(decrypt_cmd) == 0, "Image decryption should succeed");

    // Verify file sizes match (for bitmap, this indicates structural integrity)
    auto original_size = std::filesystem::file_size(original_image);
    auto decrypted_size = std::filesystem::file_size(decrypted_image);
    success &= ASSERT_TRUE(original_size == decrypted_size, "Decrypted image should have same size as original");

    // Binary comparison (for exact match)
    std::ifstream orig(original_image, std::ios::binary);
    std::ifstream decr(decrypted_image, std::ios::binary);

    std::vector<char> orig_data((std::istreambuf_iterator<char>(orig)), std::istreambuf_iterator<char>());
    std::vector<char> decr_data((std::istreambuf_iterator<char>(decr)), std::istreambuf_iterator<char>());

    success &= ASSERT_TRUE(orig_data == decr_data, "Decrypted image data should match original exactly");

    std::filesystem::remove_all(test_dir);
    PRINT_RESULTS();
    return success;
}

// SYSTEM TEST 3: Error Handling and Edge Cases
bool CommandLineToolsTest::SystemTests::test_error_scenarios() {
    TEST_SUITE("Error Scenario E2E Tests");
    bool success = true;

    const std::string test_dir = "./test_errors/";
    std::filesystem::create_directories(test_dir);

    // Test 1: Wrong key for decryption
    const std::string test_file = test_dir + "test.txt";
    const std::string encrypted_file = test_dir + "encrypted.aes";
    const std::string key1 = test_dir + "key1.key";
    const std::string key2 = test_dir + "key2.key";
    const std::string decrypted_file = test_dir + "decrypted.txt";

    SystemUtils::create_test_file(test_file, "Test content");

    // Generate two different keys
    SystemUtils::execute_cli_command(this->executable_path + " --generate-key --output " + key1);
    SystemUtils::execute_cli_command(this->executable_path + " --generate-key --output " + key2);

    // Encrypt with key1
    std::string encrypt_cmd =
        this->executable_path + " --encrypt --key " + key1 + " --input " + test_file + " --output " + encrypted_file;
    success &= ASSERT_TRUE(SystemUtils::execute_cli_command(encrypt_cmd) == 0, "Encryption should succeed");

    // Try to decrypt with key2 (should fail or produce garbage)
    std::string decrypt_cmd = this->executable_path + " --decrypt --key " + key2 +
                             " --input " + encrypted_file + " --output " + decrypted_file;
    int decrypt_result = SystemUtils::execute_cli_command(decrypt_cmd);

    // Either command should fail, or decrypted content should be garbage
    if (decrypt_result == 0 && std::filesystem::exists(decrypted_file)) {
        std::string decrypted_content = SystemUtils::read_file_content(decrypted_file);
        success &= ASSERT_TRUE(decrypted_content != "Test content", "Wrong key should not produce correct plaintext");
    } else {
        success &= ASSERT_TRUE(decrypt_result != 0, "Decryption with wrong key should fail");
    }

    // Test 2: Non-existent file
    int nonexistent_result = SystemUtils::execute_cli_command(
        this->executable_path + " --encrypt --input nonexistent.txt --output out.aes"
    );
    success &= ASSERT_TRUE(nonexistent_result != 0, "Encrypting non-existent file should fail");

    // Test 3: Invalid key file
    int invalid_key_result = SystemUtils::execute_cli_command(
        this->executable_path + " --encrypt --key invalid.key --input " + test_file + " --output out.aes"
    );
    success &= ASSERT_TRUE(invalid_key_result != 0, "Using invalid key file should fail");

    std::filesystem::remove_all(test_dir);
    PRINT_RESULTS();
    return success;
}

// SYSTEM TEST 4: Performance and Large File Handling
bool CommandLineToolsTest::SystemTests::test_large_file_performance() {
    TEST_SUITE("Large File Performance E2E Tests");
    bool success = true;

    const std::string test_dir = "./test_performance/";
    std::filesystem::create_directories(test_dir);

    // Create a moderately large test file (1MB)
    const std::string large_file = test_dir + "large_test.bin";
    const std::string encrypted_file = test_dir + "large_encrypted.aes";
    const std::string decrypted_file = test_dir + "large_decrypted.bin";
    const std::string key_file = test_dir + "perf.key";

    // Create 1MB file with pseudo-random data
    std::ofstream large_test(large_file, std::ios::binary);
    for (int i = 0; i < 1024 * 1024; ++i) {
        uint8_t byte = static_cast<uint8_t>((i * 73 + 17) % 256);  // Simple PRNG
        large_test.write(reinterpret_cast<const char*>(&byte), 1);
    }
    large_test.close();

    // Generate key
    SystemUtils::execute_cli_command(this->executable_path + " --generate-key --output " + key_file);

    // Time the encryption
    auto start_time = std::chrono::high_resolution_clock::now();

    std::string encrypt_cmd = this->executable_path + " --encrypt --mode CBC --key " + key_file +
                             " --input " + large_file + " --output " + encrypted_file;
    int encrypt_result = SystemUtils::execute_cli_command(encrypt_cmd);

    auto encrypt_end = std::chrono::high_resolution_clock::now();
    auto encrypt_duration = std::chrono::duration_cast<std::chrono::milliseconds>(encrypt_end - start_time);

    success &= ASSERT_TRUE(encrypt_result == 0, "Large file encryption should succeed");
    success &= ASSERT_TRUE(encrypt_duration.count() < 10000, "1MB encryption should complete within 10 seconds");

    // Time the decryption
    auto decrypt_start = std::chrono::high_resolution_clock::now();

    std::string decrypt_cmd = this->executable_path + " --decrypt --mode CBC --key " + key_file +
                             " --input " + encrypted_file + " --output " + decrypted_file;
    int decrypt_result = SystemUtils::execute_cli_command(decrypt_cmd);

    auto decrypt_end = std::chrono::high_resolution_clock::now();
    auto decrypt_duration = std::chrono::duration_cast<std::chrono::milliseconds>(decrypt_end - decrypt_start);

    success &= ASSERT_TRUE(decrypt_result == 0, "Large file decryption should succeed");
    success &= ASSERT_TRUE(decrypt_duration.count() < 10000, "1MB decryption should complete within 10 seconds");

    // Verify integrity
    auto original_size = std::filesystem::file_size(large_file);
    auto decrypted_size = std::filesystem::file_size(decrypted_file);
    success &= ASSERT_TRUE(original_size == decrypted_size, "Large file should maintain size after roundtrip");

    std::filesystem::remove_all(test_dir);
    PRINT_RESULTS();
    return success;
}
