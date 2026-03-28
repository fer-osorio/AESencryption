// System/E2E Testing Examples for AES File Encryption Tool
// File: system/test_file_encryption_workflows.cpp

#include "../include/raster_image_fixture.hpp"  // pulls in <gtest/gtest.h>
#include <gtest/gtest.h>
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
    return std::string("");
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
        this->encryptedOriginalLargePath += "." + SystemUtils::toFileExtension(ff);
        this->decryptedOriginalLargePath += "." + SystemUtils::toFileExtension(ff);
    }
    switch(ff){
        case FileFormat::UNKNOWN:
        case FileFormat::BINARY: {
            auto generator = [](size_t i) noexcept -> uint8_t{
                    return i & 0xFF;                                            // Equivalent to i % 256
            };
            SystemUtils::create_binary_file(
                this->originalValidPath, generator, 1024 // Building valid file
            );
            SystemUtils::create_binary_file(
                this->originalLargePath, generator, 1024*1024*3 // Building large file
            );
            }
            break;
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
            SystemUtils::create_text_file(
                this->originalLargePath,
                std::string(large_file_content.data(),
                large_file_content.size())
            );
            }
            break;
        case FileFormat::BITMAP:
            RasterImageFixture::createValidBmp(this->originalValidPath, 32, 32);      // Building valid file
            RasterImageFixture::createValidBmp(this->originalLargePath, 4096, 4096);  // Building large file
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

SystemTests::SystemTests(const std::string executable_path_, FileFormat ff):
    executable_path(executable_path_), ff_(ff) {
    this->setupTestEnvironment(ff);
}

SystemTests::~SystemTests(){
    this->cleanupTestEnvironment();
}

// SYSTEM TEST 1: Complete Text File Encryption Workflow
bool SystemTests::test_file_encryption_workflow() {
    bool success = true;

    // Step 2: Generate encryption key
    std::string gen_key_cmd =
        this->executable_path + " --generate-key --key-length 256 --output " +
        this->keyPath.string();
    int result1 = SystemUtils::execute_cli_command(
        gen_key_cmd
    );
    EXPECT_EQ(0, result1) << "Key generation should succeed";
    success &= (result1 == 0);

    bool keyCreated = std::filesystem::exists(this->keyPath);
    EXPECT_TRUE(keyCreated) << "Key file should be created";
    success &= keyCreated;

    // Step 3: Encrypt the file
    std::string encrypt_cmd =
        this->executable_path + " --mode CBC --key " +
        this->keyPath.string() + " --input " + this->originalValidPath.string()
        + " --output " + this->encryptedOriginalValidPath.string()
        + " --iv 00112233445566778899AABBCCDDEEFF";
    int result2 = SystemUtils::execute_cli_command(
        encrypt_cmd
    );

    EXPECT_EQ(0, result2) << "File encryption should succeed";
    success &= (result2 == 0);

    bool encryptedCreated = std::filesystem::exists(this->encryptedOriginalValidPath);
    EXPECT_TRUE(encryptedCreated) << "Encrypted file should be created";
    success &= encryptedCreated;

    // Step 4: Verify encrypted file is different from original
    std::vector<uint8_t> test_content = SystemUtils::read_file(
        this->originalValidPath, this->ff_ != FileFormat::TEXT
    );
    std::vector<uint8_t> encrypted_content = SystemUtils::read_file(
        this->encryptedOriginalValidPath, this->ff_ != FileFormat::TEXT
    );

    bool contentDiffers = (encrypted_content != test_content);
    EXPECT_TRUE(contentDiffers) << "Encrypted content should differ from original";
    success &= contentDiffers;

    // Step 5: Decrypt the file
    std::string decrypt_cmd =
        this->executable_path + " --decrypt --mode CBC --key " + this->keyPath.string() +
        " --input " + this->encryptedOriginalValidPath.string() +
        " --output " + this->decryptedOriginalValidPath.string() +
        " --iv 00112233445566778899AABBCCDDEEFF";
    int result3 = SystemUtils::execute_cli_command(
        decrypt_cmd
    );

    EXPECT_EQ(0, result3) << "File decryption should succeed";
    success &= (result3 == 0);

    bool decryptedCreated = std::filesystem::exists(this->decryptedOriginalValidPath);
    EXPECT_TRUE(decryptedCreated) << "Decrypted file should be created";
    success &= decryptedCreated;

    // Step 6: Verify decrypted content matches original
    std::vector<uint8_t> decrypted_content = SystemUtils::read_file(
        this->decryptedOriginalValidPath, this->ff_ != FileFormat::TEXT
    );

    bool contentMatches = (decrypted_content == test_content);
    EXPECT_TRUE(contentMatches) << "Decrypted content should match original";
    success &= contentMatches;

    if (!contentMatches) {
        std::cout << "Original size: " << test_content.size() << std::endl;
        std::cout << "Decrypted size: " << decrypted_content.size() << std::endl;

        if (test_content.size() == decrypted_content.size()) {
            for (size_t i = 0; i < test_content.size(); i++) {
                if (test_content[i] != decrypted_content[i]) {
                    std::cout << "First mismatch at byte " <<
                        i << std::endl;
                    std::cout << "Original: " << std::hex <<
                        static_cast<int>(test_content[i]) << std::endl;
                    std::cout << "Decrypted: " << std::hex<<
                        static_cast<int>(decrypted_content[i]) << std::endl;
                    break;
                }
            }
        }
    }

    return success;
}

// SYSTEM TEST 2: Error Handling and Edge Cases
bool SystemTests::test_error_scenarios() {
    bool success = true;

    const fs::path second_key = this->testDataDir / "second_key.bin";

    // Generate two different keys
    SystemUtils::execute_cli_command(
        this->executable_path + " --generate-key --output " +
        this->keyPath.string()
    );
    SystemUtils::execute_cli_command(
        this->executable_path + " --generate-key --output " +
        second_key.string()
    );

    // Encrypt with key1
    std::string encrypt_cmd =
        this->executable_path + " --key " + this->keyPath.string() +
        " --input " + this->originalValidPath.string() +
        " --output " + this->encryptedOriginalValidPath.string();
    bool encryptSucceeded = (SystemUtils::execute_cli_command(encrypt_cmd) == 0);
    EXPECT_TRUE(encryptSucceeded) << "Encryption should succeed";
    success &= encryptSucceeded;

    // Try to decrypt with second_key (should fail or produce garbage)
    std::string decrypt_cmd = this->executable_path + " --decrypt --key "
        + second_key.string() + " --input " +
        this->encryptedOriginalValidPath.string() +
        " --output " + this->decryptedOriginalValidPath.string();
    int decrypt_result = SystemUtils::execute_cli_command(
        decrypt_cmd
    );
    // Either command should fail, or decrypted content should be garbage
    if (decrypt_result == 0 && std::filesystem::exists(this->decryptedOriginalValidPath)) {
        std::vector<uint8_t> original_content = SystemUtils::read_file(
            this->originalValidPath.string(), this->ff_ != FileFormat::TEXT
        );
        std::vector<uint8_t> decrypted_content = SystemUtils::read_file(
            this->decryptedOriginalValidPath.string(), this->ff_ != FileFormat::TEXT
        );
        bool wrongKeyProducesGarbage = (decrypted_content != original_content);
        EXPECT_TRUE(wrongKeyProducesGarbage) << "Wrong key should not produce correct plaintext";
        success &= wrongKeyProducesGarbage;
    } else {
        bool wrongKeyFails = (decrypt_result != 0);
        EXPECT_TRUE(wrongKeyFails) << "Decryption with wrong key should fail";
        success &= wrongKeyFails;
    }

    // Test 2: Non-existent file
    int nonexistent_result = SystemUtils::execute_cli_command(
        this->executable_path + " --input " +
        this->nonexistentPath.string() + " --output nonexistent_out.bin"
    );
    bool nonexistentFails = (nonexistent_result != 0);
    EXPECT_TRUE(nonexistentFails) << "Encrypting non-existent file should fail";
    success &= nonexistentFails;

    // Test 3: Invalid key file
    int invalid_key_result = SystemUtils::execute_cli_command(
        this->executable_path + " --key invalid.key --input " + this->originalValidPath.string() + " --output out.aes"
    );
    bool invalidKeyFails = (invalid_key_result != 0);
    EXPECT_TRUE(invalidKeyFails) << "Using invalid key file should fail";
    success &= invalidKeyFails;

    return success;
}

// SYSTEM TEST 4: JPEG encryption saves output as PNG
bool SystemTests::test_jpeg_encryption_saves_as_png() {
    bool success = true;

    // Generate key
    std::string gen_key_cmd =
        this->executable_path + " --generate-key --output " +
        this->keyPath.string();
    SystemUtils::execute_cli_command(gen_key_cmd);

    // Create a JPEG input
    const fs::path jpegInput  = this->testDataDir / "jpeg_input.jpg";
    const fs::path encJpg     = this->testDataDir / "enc.jpg";
    const fs::path encPng     = this->testDataDir / "enc.png";
    const fs::path decJpg     = this->testDataDir / "dec.jpg";

    RasterImageFixture::createValidJpeg(jpegInput, 32, 32);

    // Encrypt — tool should redirect output to enc.png
    std::string encrypt_cmd =
        this->executable_path + " --key " + this->keyPath.string() +
        " --input " + jpegInput.string() +
        " --output " + encJpg.string() +
        " --iv 00112233445566778899AABBCCDDEEFF";
    int enc_result = SystemUtils::execute_cli_command(encrypt_cmd);
    EXPECT_EQ(0, enc_result) << "JPEG encryption should succeed";
    success &= (enc_result == 0);

    bool pngCreated = fs::exists(encPng);
    EXPECT_TRUE(pngCreated) << "Encrypted output should be saved as .png";
    success &= pngCreated;

    bool jpgNotCreated = !fs::exists(encJpg);
    EXPECT_TRUE(jpgNotCreated) << "No .jpg output should be created";
    success &= jpgNotCreated;

    // Decrypt the PNG back to JPEG
    std::string decrypt_cmd =
        this->executable_path + " --decrypt --key " + this->keyPath.string() +
        " --input " + encPng.string() +
        " --output " + decJpg.string() +
        " --iv 00112233445566778899AABBCCDDEEFF";
    int dec_result = SystemUtils::execute_cli_command(decrypt_cmd);
    EXPECT_EQ(0, dec_result) << "Decryption of PNG to JPEG should succeed";
    success &= (dec_result == 0);

    bool decCreated = fs::exists(decJpg);
    EXPECT_TRUE(decCreated) << "Decrypted JPEG should be created";
    success &= decCreated;

    return success;
}

// SYSTEM TEST 3: Performance and Large File Handling
bool SystemTests::test_large_file_performance() {
    bool success = true;

    // Generate key
    SystemUtils::execute_cli_command(
        this->executable_path + " --generate-key --output " + this->keyPath.string()
    );


    std::string encrypt_cmd = this->executable_path + " --mode CBC --key " + this->keyPath.string() +
        " --input " + this->originalLargePath.string() +
        " --output " + this->encryptedOriginalLargePath.string() +
        " --iv 00112233445566778899AABBCCDDEEFF";

    // Time the encryption
    auto start_time = std::chrono::high_resolution_clock::now();
    int encrypt_result = SystemUtils::execute_cli_command(
        encrypt_cmd
    );
    auto encrypt_end = std::chrono::high_resolution_clock::now();
    auto encrypt_duration = std::chrono::duration_cast<std::chrono::milliseconds>(encrypt_end - start_time);

    bool encryptSucceeded = (encrypt_result == 0);
    EXPECT_TRUE(encryptSucceeded) << "Large file encryption should succeed";
    success &= encryptSucceeded;

    if (encryptSucceeded) {
        bool encryptFast = (encrypt_duration.count() < 10000);
        EXPECT_TRUE(encryptFast)
            << "48MB encryption should complete within 10 seconds (lasted "
            << encrypt_duration.count() << " milliseconds)";
        success &= encryptFast;
    }

    std::string decrypt_cmd = this->executable_path +
        " --decrypt --mode CBC --key " + this->keyPath.string() +
        " --input " + this->encryptedOriginalLargePath.string() +
        " --output " + this->decryptedOriginalLargePath.string() +
        " --iv 00112233445566778899AABBCCDDEEFF";

    // Time the decryption
    auto decrypt_start = std::chrono::high_resolution_clock::now();
    int decrypt_result = SystemUtils::execute_cli_command(
        decrypt_cmd
    );
    auto decrypt_end = std::chrono::high_resolution_clock::now();
    auto decrypt_duration = std::chrono::duration_cast<std::chrono::milliseconds>(decrypt_end - decrypt_start);

    bool decryptSucceeded = (decrypt_result == 0);
    EXPECT_TRUE(decryptSucceeded) << "Large file decryption should succeed";
    success &= decryptSucceeded;

    if (decryptSucceeded) {
        bool decryptFast = (decrypt_duration.count() < 10000);
        EXPECT_TRUE(decryptFast)
            << "48MB decryption should complete within 10 seconds (lasted "
            << decrypt_duration.count() << " milliseconds)";
        success &= decryptFast;
    }

    // Verify integrity
    auto original_size = std::filesystem::file_size(this->originalLargePath);
    auto decrypted_size = std::filesystem::file_size(this->decryptedOriginalLargePath);

    bool sizeMatches = (original_size == decrypted_size);
    EXPECT_TRUE(sizeMatches) << "Large file should maintain size after roundtrip";
    success &= sizeMatches;

    return success;
}
