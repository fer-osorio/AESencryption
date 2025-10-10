// System/E2E Testing Examples for AES File Encryption Tool
// File: system/test_file_encryption_workflows.cpp

#include "../include/test_framework.hpp"
#include "../include/bitmap_fixture.hpp"
#include "../include/system_workflows.hpp"
#include <filesystem>
#include <fstream>
#include <cstdlib>
#include <string>

using namespace CommandLineToolsTest;

// Helper function to execute command line tool
int SystemUtils::execute_cli_command(const std::string& command) {
    return std::system(command.c_str());
}

// Helper to create text files
void SystemUtils::create_text_file(const std::string& filepath, const std::string& content) {
    std::ofstream file;
    file.open(filepath);
    if(!file){
        throw std::runtime_error("Failed to create file: " + filepath);
    }
    file << content;
    file.close();
}

// Helper to create binary files
void SystemUtils::create_binary_file(const std::string& filepath, const std::vector<uint8_t>& content) {
    std::ofstream file;
    file.open(filepath, std::ios::binary);
    if(!file){
        throw std::runtime_error("Failed to create file: " + filepath);
    }
    if(!file.write(reinterpret_cast<const char*>(content.data()), content.size()) ){
        throw std::runtime_error("Failed to write file: " + filepath);
    }
    file.close();
}

// Helper to create binary files
void SystemUtils::create_binary_file(const std::string& filepath, std::function<uint8_t(size_t)> generator, size_t file_size) {
    std::ofstream file;
    file.open(filepath, std::ios::binary);
    if(!file){
        throw std::runtime_error("Failed to create file: " + filepath);
    }
    std::vector<uint8_t> content(file_size);
    for(size_t i = 0; i < file_size; i++) content[i] = generator(i);
    if(!file.write(reinterpret_cast<const char*>(content.data()), content.size()) ){
        throw std::runtime_error("Failed to write file: " + filepath);
    }
    file.close();
}

// Helper to read file content
std::vector<uint8_t> SystemUtils::read_file(const std::string& filepath, bool isBinary) {
    std::ifstream file;
    if(isBinary) file.open(filepath, std::ios::binary);
    else file.open(filepath);
    if(!file){
        throw std::runtime_error("Failed to open file: " + filepath);
    }
    size_t size = std::filesystem::file_size(filepath);
    std::vector<uint8_t> content(size);
    if (!file.read(reinterpret_cast<char*>(content.data()), size)) {
        throw std::runtime_error("Failed to read file: " + filepath);
    }
    return content;
}

std::string SystemUtils::toFileExtension(FileFormat ff){
    switch(ff){
        case FileFormat::UNKNOWN:
            return std::string("");
        case FileFormat::BINARY:
            return std::string("bin");
        case FileFormat::TEXT:
            return std::string("txt");
        case FileFormat::BITMAP:
            return std::string("bmp");
    }
}

void SystemTests::setupTestEnvironment(FileFormat ff){
    // Create test data directory
    if (!fs::exists(this->testDataDir)) {
        fs::create_directory(this->testDataDir);
    }
    if(ff != FileFormat::UNKNOWN){
        // Valid and large test file paths
        this->originalValidPath += "." + SystemUtils::toFileExtension(ff);
        this->originalLargePath += "." + SystemUtils::toFileExtension(ff);
        // Non-existent test file path
        this->nonexistentPath += "." + SystemUtils::toFileExtension(ff);
        // Encrypted and decrypted file paths
        this->encryptedOriginalValidPath += "." + SystemUtils::toFileExtension(ff);
        this->decryptedOriginalValidPath += "." + SystemUtils::toFileExtension(ff);
    }
    switch(ff){
        case FileFormat::UNKNOWN:
        case FileFormat::BINARY: {
            auto generator = [](size_t i) -> uint8_t{
                    return i & 0xFF;                                            // Equivalent to i % 256
            };
            SystemUtils::create_binary_file(this->originalValidPath, generator, 1024);  // Building valid file
            SystemUtils::create_binary_file(this->originalLargePath, generator, 1024*1024*3); // Building large file
            break;
            }
        case FileFormat::TEXT: {
            SystemUtils::create_text_file(                                      // Building valid file
                this->originalValidPath,
                "Everything that you thought had meaning: every hope, dream, or moment of happiness. "
                "None of it matters as you lie bleeding out on the battlefield. None of it changes "
                "what a speeding rock does to a body, we all die. But does that mean our lives are "
                "meaningless? Does that mean that there was no point in our being born? Would you "
                "say that of our slain comrades? What about their lives? Were they meaningless?... "
                "They were not! Their memory serves as an example to us all! The courageous fallen! "
                "The anguished fallen! Their lives have meaning because we the living refuse to forget "
                "them! And as we ride to certain death, we trust our successors to do the same for us! "
                "Because my soldiers do not buckle or yield when faced with the cruelty of this world! "
                "My soldiers push forward! My soldiers scream out! My soldiers RAAAAAGE!\n"
                "\n\t~ Erwin's famous and final speech as he leads the Survey Corps on a suicide charge."
            );
            const std::vector<char> large_file_content(1024*1024*3, 'z');       // Building large file
            SystemUtils::create_text_file(this->originalLargePath, std::string(large_file_content.data(), large_file_content.size()) );
            }
        case FileFormat::BITMAP:
            BitmapTestFixture::createValidBitmap(this->originalValidPath, 32, 32);      // Building valid file
            BitmapTestFixture::createValidBitmap(this->originalLargePath, 1024, 1024);  // Building large file
            break;
    }
}

void SystemTests::cleanupTestEnvironment(){
    // Clean up test files
    if (fs::exists(this->testDataDir)) {
        for (auto& entry : fs::directory_iterator(this->testDataDir)) {
            if (entry.path().filename() != ".gitkeep") {    // Avoid delete directories tracked by git
                fs::remove(entry.path());
            }
        }
    }
}

SystemTests::SystemTests(const std::string executable_path_, FileFormat ff): executable_path(executable_path_), ff_(ff) {
    this->setupTestEnvironment(ff);
}

SystemTests::~SystemTests(){
    this->cleanupTestEnvironment();
}

// SYSTEM TEST 1: Complete Text File Encryption Workflow
bool SystemTests::test_text_file_encryption_workflow() {
    TEST_SUITE("Text File Encryption E2E Workflow");
    bool success = true;

    // Step 2: Generate encryption key
    std::string gen_key_cmd = this->executable_path + " --generate-key --key-size 256 --output " + this->keyPath.string();
    int result1 = SystemUtils::execute_cli_command(gen_key_cmd);
    success &= ASSERT_TRUE(result1 == 0, "Key generation should succeed");
    success &= ASSERT_TRUE(std::filesystem::exists(this->keyPath), "Key file should be created");

    // Step 3: Encrypt the file
    std::string encrypt_cmd =
        this->executable_path + " --encrypt --mode CBC --key " + this->keyPath.string() +
        " --input " + this->originalValidPath.string() + " --output " + this->encryptedOriginalValidPath.string();
    int result2 = SystemUtils::execute_cli_command(encrypt_cmd);
    success &= ASSERT_TRUE(result2 == 0, "File encryption should succeed");
    success &= ASSERT_TRUE(std::filesystem::exists(this->encryptedOriginalValidPath), "Encrypted file should be created");

    // Step 4: Verify encrypted file is different from original
    std::vector<uint8_t> test_content = SystemUtils::read_file(this->originalValidPath, this->ff_ != FileFormat::TEXT);
    std::vector<uint8_t> encrypted_content = SystemUtils::read_file(this->encryptedOriginalValidPath, this->ff_ != FileFormat::TEXT);
    success &= ASSERT_TRUE(encrypted_content != test_content, "Encrypted content should differ from original");

    // Step 5: Decrypt the file
    std::string decrypt_cmd
        = this->executable_path + " --decrypt --mode CBC --key " + this->keyPath.string() +
        " --input " + this->encryptedOriginalValidPath.string() + " --output " + this->decryptedOriginalValidPath.string();
    int result3 = SystemUtils::execute_cli_command(decrypt_cmd);
    success &= ASSERT_TRUE(result3 == 0, "File decryption should succeed");
    success &= ASSERT_TRUE(std::filesystem::exists(this->decryptedOriginalValidPath), "Decrypted file should be created");

    // Step 6: Verify decrypted content matches original
    std::vector<uint8_t> decrypted_content = SystemUtils::read_file(this->decryptedOriginalValidPath, this->ff_ != FileFormat::TEXT);
    success &= ASSERT_TRUE(decrypted_content == test_content, "Decrypted content should match original");

    PRINT_RESULTS();
    return success;
}

// SYSTEM TEST 2: Image File Encryption Workflow
bool SystemTests::test_image_encryption_workflow() {
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
    std::string gen_key_cmd = this->executable_path + " --generate-key --key-size 128 --output " + this->keyPath.string();
    success &= ASSERT_TRUE(SystemUtils::execute_cli_command(gen_key_cmd) == 0, "Key generation should succeed");

    // Encrypt image
    std::string encrypt_cmd = this->executable_path + " --encrypt --mode ECB --key " + this->keyPath.string() +
                             " --input " + original_image + " --output " + encrypted_image + " --type bitmap";
    success &= ASSERT_TRUE(SystemUtils::execute_cli_command(encrypt_cmd) == 0, "Image encryption should succeed");

    // Decrypt image
    std::string decrypt_cmd = this->executable_path + " --decrypt --mode ECB --key " + this->keyPath.string() +
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
bool SystemTests::test_error_scenarios() {
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

    SystemUtils::create_file(test_file, "Test content");

    // Generate two different keys
    SystemUtils::execute_cli_command(this->executable_path + " --generate-key --output " + key1);
    SystemUtils::execute_cli_command(this->executable_path + " --generate-key --output " + key2);

    // Encrypt with key1
    std::string encrypt_cmd =
        this->executable_path + " --encrypt --key " + key1 + " --input " + test_file + " --output " + this->encryptedPath.string();
    success &= ASSERT_TRUE(SystemUtils::execute_cli_command(encrypt_cmd) == 0, "Encryption should succeed");

    // Try to decrypt with key2 (should fail or produce garbage)
    std::string decrypt_cmd = this->executable_path + " --decrypt --key " + key2 +
                             " --input " + this->encryptedPath.string() + " --output " + decrypted_file;
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
bool SystemTests::test_large_file_performance() {
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
    SystemUtils::execute_cli_command(this->executable_path + " --generate-key --output " + this->keyPath.string());

    // Time the encryption
    auto start_time = std::chrono::high_resolution_clock::now();

    std::string encrypt_cmd = this->executable_path + " --encrypt --mode CBC --key " + this->keyPath.string() +
                             " --input " + large_file + " --output " + this->encryptedPath.string();
    int encrypt_result = SystemUtils::execute_cli_command(encrypt_cmd);

    auto encrypt_end = std::chrono::high_resolution_clock::now();
    auto encrypt_duration = std::chrono::duration_cast<std::chrono::milliseconds>(encrypt_end - start_time);

    success &= ASSERT_TRUE(encrypt_result == 0, "Large file encryption should succeed");
    success &= ASSERT_TRUE(encrypt_duration.count() < 10000, "1MB encryption should complete within 10 seconds");

    // Time the decryption
    auto decrypt_start = std::chrono::high_resolution_clock::now();

    std::string decrypt_cmd = this->executable_path + " --decrypt --mode CBC --key " + this->keyPath.string() +
                             " --input " + this->encryptedPath.string() + " --output " + decrypted_file;
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
