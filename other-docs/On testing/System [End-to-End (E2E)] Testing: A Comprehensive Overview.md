# System/End-to-End (E2E) Testing: A Comprehensive Overview

## **Definition and Core Purpose**

**System Testing** (also called End-to-End or E2E Testing) is a testing methodology that validates the complete integrated system by testing entire workflows from the user's perspective. It verifies that all components work together correctly in a production-like environment to meet specified requirements.

**Core Purpose**:
- Validate that the system works as a whole, not just individual parts
- Test real user scenarios and workflows
- Verify that business requirements are met
- Catch issues that only emerge when components interact in realistic conditions
- Ensure the system behaves correctly in its intended deployment environment

## **Historical Context and Evolution**

### **Early Software Era (1950s-1960s)**
- **Monolithic Systems**: Early software was often single, large programs
- **Manual Testing**: System testing was primarily manual, following written test procedures
- **Hardware Integration**: Focus was on ensuring software worked with specific hardware configurations

### **Structured Programming Era (1970s-1980s)**
- **Waterfall Model**: System testing became the final phase before deployment
- **Big Bang Integration**: All components integrated at once, then system tested
- **Documentation-Heavy**: Extensive test plans and procedures were written in advance

### **Object-Oriented and GUI Era (1990s)**
- **User Interface Testing**: System testing expanded to include comprehensive UI testing
- **Client-Server Architecture**: Testing distributed systems became more complex
- **Automated Test Tools**: First generation of automated testing tools emerged

### **Web and Agile Era (2000s)**
- **Web-Based E2E Testing**: Tools like Selenium revolutionized browser-based testing
- **Continuous Integration**: System tests integrated into automated build pipelines
- **Agile Methodology**: System testing shifted from end-phase to continuous activity

### **DevOps and Cloud Era (2010s-Present)**
- **Container-Based Testing**: Docker and Kubernetes enabled realistic test environments
- **Infrastructure as Code**: Test environments became reproducible and version-controlled
- **Microservices Testing**: Complex distributed system testing across multiple services
- **API-First Testing**: Testing through APIs rather than just UIs

## **System/E2E Testing in Practice**

```cpp
// System/E2E Testing Examples for AES File Encryption Tool
// File: system/test_file_encryption_workflows.cpp

#include "test_framework.hpp"
#include <filesystem>
#include <fstream>
#include <cstdlib>
#include <string>

namespace SystemTestUtils {
    // Helper function to execute command line tool
    int execute_cli_command(const std::string& command) {
        return std::system(command.c_str());
    }
    
    // Helper to create test files
    void create_test_file(const std::string& filename, const std::string& content) {
        std::ofstream file(filename);
        file << content;
        file.close();
    }
    
    // Helper to read file content
    std::string read_file_content(const std::string& filename) {
        std::ifstream file(filename);
        std::string content((std::istreambuf_iterator<char>(file)),
                           std::istreambuf_iterator<char>());
        return content;
    }
    
    // Helper to create test bitmap
    void create_test_bitmap(const std::string& filename, size_t width, size_t height) {
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
}

// SYSTEM TEST 1: Complete Text File Encryption Workflow
void test_text_file_encryption_workflow() {
    TEST_SUITE("Text File Encryption E2E Workflow");
    
    // Setup: Create test environment
    const std::string test_dir = "./test_temp/";
    std::filesystem::create_directories(test_dir);
    
    const std::string original_file = test_dir + "original.txt";
    const std::string encrypted_file = test_dir + "encrypted.aes";
    const std::string decrypted_file = test_dir + "decrypted.txt";
    const std::string key_file = test_dir + "test.key";
    
    // Test data
    const std::string test_content = "This is a test file for AES encryption.\n"
                                   "It contains multiple lines of text.\n"
                                   "Special characters: !@#$%^&*()_+{}|:<>?\n"
                                   "Numbers: 1234567890\n";
    
    // Step 1: Create original file
    SystemTestUtils::create_test_file(original_file, test_content);
    
    // Step 2: Generate encryption key
    std::string gen_key_cmd = "./bin/aes-tool --generate-key --key-size 256 --output " + key_file;
    int result1 = SystemTestUtils::execute_cli_command(gen_key_cmd);
    ASSERT_TRUE(result1 == 0, "Key generation should succeed");
    ASSERT_TRUE(std::filesystem::exists(key_file), "Key file should be created");
    
    // Step 3: Encrypt the file
    std::string encrypt_cmd = "./bin/aes-tool --encrypt --mode CBC --key " + key_file + 
                             " --input " + original_file + " --output " + encrypted_file;
    int result2 = SystemTestUtils::execute_cli_command(encrypt_cmd);
    ASSERT_TRUE(result2 == 0, "File encryption should succeed");
    ASSERT_TRUE(std::filesystem::exists(encrypted_file), "Encrypted file should be created");
    
    // Step 4: Verify encrypted file is different from original
    std::string encrypted_content = SystemTestUtils::read_file_content(encrypted_file);
    ASSERT_TRUE(encrypted_content != test_content, "Encrypted content should differ from original");
    
    // Step 5: Decrypt the file
    std::string decrypt_cmd = "./bin/aes-tool --decrypt --mode CBC --key " + key_file +
                             " --input " + encrypted_file + " --output " + decrypted_file;
    int result3 = SystemTestUtils::execute_cli_command(decrypt_cmd);
    ASSERT_TRUE(result3 == 0, "File decryption should succeed");
    ASSERT_TRUE(std::filesystem::exists(decrypted_file), "Decrypted file should be created");
    
    // Step 6: Verify decrypted content matches original
    std::string decrypted_content = SystemTestUtils::read_file_content(decrypted_file);
    ASSERT_TRUE(decrypted_content == test_content, "Decrypted content should match original");
    
    // Cleanup
    std::filesystem::remove_all(test_dir);
    
    PRINT_RESULTS();
}

// SYSTEM TEST 2: Image File Encryption Workflow
void test_image_encryption_workflow() {
    TEST_SUITE("Image File Encryption E2E Workflow");
    
    const std::string test_dir = "./test_images/";
    std::filesystem::create_directories(test_dir);
    
    const std::string original_image = test_dir + "test.bmp";
    const std::string encrypted_image = test_dir + "test_encrypted.bmp";
    const std::string decrypted_image = test_dir + "test_decrypted.bmp";
    const std::string key_file = test_dir + "image.key";
    
    // Create test bitmap
    SystemTestUtils::create_test_bitmap(original_image, 100, 100);
    
    // Generate key
    std::string gen_key_cmd = "./bin/aes-tool --generate-key --key-size 128 --output " + key_file;
    ASSERT_TRUE(SystemTestUtils::execute_cli_command(gen_key_cmd) == 0, "Key generation should succeed");
    
    // Encrypt image
    std::string encrypt_cmd = "./bin/aes-tool --encrypt --mode ECB --key " + key_file +
                             " --input " + original_image + " --output " + encrypted_image + " --type bitmap";
    ASSERT_TRUE(SystemTestUtils::execute_cli_command(encrypt_cmd) == 0, "Image encryption should succeed");
    
    // Decrypt image  
    std::string decrypt_cmd = "./bin/aes-tool --decrypt --mode ECB --key " + key_file +
                             " --input " + encrypted_image + " --output " + decrypted_image + " --type bitmap";
    ASSERT_TRUE(SystemTestUtils::execute_cli_command(decrypt_cmd) == 0, "Image decryption should succeed");
    
    // Verify file sizes match (for bitmap, this indicates structural integrity)
    auto original_size = std::filesystem::file_size(original_image);
    auto decrypted_size = std::filesystem::file_size(decrypted_image);
    ASSERT_TRUE(original_size == decrypted_size, "Decrypted image should have same size as original");
    
    // Binary comparison (for exact match)
    std::ifstream orig(original_image, std::ios::binary);
    std::ifstream decr(decrypted_image, std::ios::binary);
    
    std::vector<char> orig_data((std::istreambuf_iterator<char>(orig)),
                                std::istreambuf_iterator<char>());
    std::vector<char> decr_data((std::istreambuf_iterator<char>(decr)),
                                std::istreambuf_iterator<char>());
    
    ASSERT_TRUE(orig_data == decr_data, "Decrypted image data should match original exactly");
    
    std::filesystem::remove_all(test_dir);
    PRINT_RESULTS();
}

// SYSTEM TEST 3: Error Handling and Edge Cases
void test_error_scenarios() {
    TEST_SUITE("Error Scenario E2E Tests");
    
    const std::string test_dir = "./test_errors/";
    std::filesystem::create_directories(test_dir);
    
    // Test 1: Wrong key for decryption
    const std::string test_file = test_dir + "test.txt";
    const std::string encrypted_file = test_dir + "encrypted.aes";
    const std::string key1 = test_dir + "key1.key";
    const std::string key2 = test_dir + "key2.key";
    const std::string decrypted_file = test_dir + "decrypted.txt";
    
    SystemTestUtils::create_test_file(test_file, "Test content");
    
    // Generate two different keys
    SystemTestUtils::execute_cli_command("./bin/aes-tool --generate-key --output " + key1);
    SystemTestUtils::execute_cli_command("./bin/aes-tool --generate-key --output " + key2);
    
    // Encrypt with key1
    std::string encrypt_cmd = "./bin/aes-tool --encrypt --key " + key1 + 
                             " --input " + test_file + " --output " + encrypted_file;
    ASSERT_TRUE(SystemTestUtils::execute_cli_command(encrypt_cmd) == 0, "Encryption should succeed");
    
    // Try to decrypt with key2 (should fail or produce garbage)
    std::string decrypt_cmd = "./bin/aes-tool --decrypt --key " + key2 +
                             " --input " + encrypted_file + " --output " + decrypted_file;
    int decrypt_result = SystemTestUtils::execute_cli_command(decrypt_cmd);
    
    // Either command should fail, or decrypted content should be garbage
    if (decrypt_result == 0 && std::filesystem::exists(decrypted_file)) {
        std::string decrypted_content = SystemTestUtils::read_file_content(decrypted_file);
        ASSERT_TRUE(decrypted_content != "Test content", "Wrong key should not produce correct plaintext");
    } else {
        ASSERT_TRUE(decrypt_result != 0, "Decryption with wrong key should fail");
    }
    
    // Test 2: Non-existent file
    int nonexistent_result = SystemTestUtils::execute_cli_command(
        "./bin/aes-tool --encrypt --input nonexistent.txt --output out.aes");
    ASSERT_TRUE(nonexistent_result != 0, "Encrypting non-existent file should fail");
    
    // Test 3: Invalid key file
    int invalid_key_result = SystemTestUtils::execute_cli_command(
        "./bin/aes-tool --encrypt --key invalid.key --input " + test_file + " --output out.aes");
    ASSERT_TRUE(invalid_key_result != 0, "Using invalid key file should fail");
    
    std::filesystem::remove_all(test_dir);
    PRINT_RESULTS();
}

// SYSTEM TEST 4: Performance and Large File Handling
void test_large_file_performance() {
    TEST_SUITE("Large File Performance E2E Tests");
    
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
    SystemTestUtils::execute_cli_command("./bin/aes-tool --generate-key --output " + key_file);
    
    // Time the encryption
    auto start_time = std::chrono::high_resolution_clock::now();
    
    std::string encrypt_cmd = "./bin/aes-tool --encrypt --mode CBC --key " + key_file +
                             " --input " + large_file + " --output " + encrypted_file;
    int encrypt_result = SystemTestUtils::execute_cli_command(encrypt_cmd);
    
    auto encrypt_end = std::chrono::high_resolution_clock::now();
    auto encrypt_duration = std::chrono::duration_cast<std::chrono::milliseconds>(encrypt_end - start_time);
    
    ASSERT_TRUE(encrypt_result == 0, "Large file encryption should succeed");
    ASSERT_TRUE(encrypt_duration.count() < 10000, "1MB encryption should complete within 10 seconds");
    
    // Time the decryption
    auto decrypt_start = std::chrono::high_resolution_clock::now();
    
    std::string decrypt_cmd = "./bin/aes-tool --decrypt --mode CBC --key " + key_file +
                             " --input " + encrypted_file + " --output " + decrypted_file;
    int decrypt_result = SystemTestUtils::execute_cli_command(decrypt_cmd);
    
    auto decrypt_end = std::chrono::high_resolution_clock::now();
    auto decrypt_duration = std::chrono::duration_cast<std::chrono::milliseconds>(decrypt_end - decrypt_start);
    
    ASSERT_TRUE(decrypt_result == 0, "Large file decryption should succeed");
    ASSERT_TRUE(decrypt_duration.count() < 10000, "1MB decryption should complete within 10 seconds");
    
    // Verify integrity
    auto original_size = std::filesystem::file_size(large_file);
    auto decrypted_size = std::filesystem::file_size(decrypted_file);
    ASSERT_TRUE(original_size == decrypted_size, "Large file should maintain size after roundtrip");
    
    std::filesystem::remove_all(test_dir);
    PRINT_RESULTS();
}

int main() {
    std::cout << "=== System/E2E Testing for AES File Encryption Tool ===" << std::endl;
    
    test_text_file_encryption_workflow();
    test_image_encryption_workflow(); 
    test_error_scenarios();
    test_large_file_performance();
    
    std::cout << "\n=== All System Tests Complete ===" << std::endl;
    return 0;
}
```

## **Use Cases and Applications**

### **1. Financial Systems**
- **ATM Transactions**: Test complete withdrawal workflow from card insertion to cash dispensing
- **Online Banking**: Test login → transfer funds → confirmation → account update
- **Payment Processing**: Test credit card transaction from merchant to bank settlement

### **2. E-commerce Platforms**
- **Purchase Workflow**: Browse → add to cart → checkout → payment → order fulfillment → delivery tracking
- **User Registration**: Sign up → email verification → profile setup → first purchase
- **Return Process**: Request return → approval → shipping → refund processing

### **3. Healthcare Systems**
- **Patient Management**: Registration → appointment → diagnosis → treatment → billing → insurance processing
- **Electronic Health Records**: Data entry → validation → storage → retrieval → sharing between providers
- **Medical Device Integration**: Device readings → data processing → alert generation → clinical response

### **4. Automotive Systems**
- **Autonomous Driving**: Sensor input → data processing → decision making → vehicle control → safety monitoring
- **Infotainment Systems**: User input → system response → media playback → navigation → connectivity

### **5. Your AES File Encryption Tool**
- **Complete Encryption Workflow**: File selection → key generation → encryption → storage → retrieval → decryption → verification
- **Batch Processing**: Multiple files → progress tracking → error handling → completion reporting
- **Integration Testing**: Command line interface → file system operations → crypto operations → user feedback

## **Common Misuses and Anti-Patterns**

### **1. Testing Too Much Detail (Unit Test Disguised as System Test)**
```cpp
// WRONG - This is actually a unit test
void test_aes_encryption_algorithm() {
    uint8_t key[16] = {...};
    uint8_t plaintext[16] = {...};
    uint8_t ciphertext[16];
    
    aes_encrypt(plaintext, key, ciphertext);
    assert(memcmp(ciphertext, expected, 16) == 0);
}

// RIGHT - Actual system test
void test_file_encryption_workflow() {
    system("./aes-tool --encrypt file.txt --key mykey.key --output encrypted.aes");
    system("./aes-tool --decrypt encrypted.aes --key mykey.key --output decrypted.txt");
    assert(files_are_identical("file.txt", "decrypted.txt"));
}
```

### **2. Over-Mocking (Defeating the Purpose)**
```cpp
// WRONG - Mocking everything defeats system test purpose
void test_file_encryption_system() {
    MockFileSystem mock_fs;
    MockCryptoEngine mock_crypto;
    MockUserInterface mock_ui;
    
    // This is no longer testing the real system!
}
```

### **3. Flaky Tests Due to External Dependencies**
```cpp
// PROBLEMATIC - Depends on external network
void test_license_validation() {
    // Calls external license server
    // Fails when network is down or server is busy
    bool result = validate_license_online();
    assert(result == true);
}
```

### **4. Testing Implementation Details**
```cpp
// WRONG - Testing internal implementation
void test_memory_allocation_pattern() {
    // System tests should focus on user-visible behavior
    // Not internal memory management patterns
}
```

### **5. Unrealistic Test Data**
```cpp
// PROBLEMATIC - Unrealistic test scenarios
void test_encryption_with_perfect_conditions() {
    // Always uses same key, same file size, same content
    // Doesn't test real-world variability
}
```

## **Best Practices for System/E2E Testing**

### **1. Test Realistic Scenarios**
- Use real file sizes and types that users would encounter
- Include edge cases (empty files, very large files, special characters)
- Test with realistic data volumes and complexity

### **2. Environment Isolation**
- Use containerized test environments
- Clean up test artifacts after each test
- Avoid dependencies on external systems when possible

### **3. Clear Pass/Fail Criteria**
- Define specific, measurable success criteria
- Test both positive and negative scenarios
- Include performance benchmarks where relevant

### **4. Maintainable Test Infrastructure**
- Use helper functions to reduce code duplication
- Create reusable test utilities
- Document test setup and teardown procedures

### **5. Balance Coverage and Execution Time**
- Focus on critical user workflows
- Use risk-based testing to prioritize scenarios
- Consider parallel execution for faster feedback

## **System Testing vs Other Testing Types**

| Aspect | Unit Tests | Integration Tests | System Tests |
|--------|------------|-------------------|--------------|
| **Scope** | Single function/class | Component interfaces | Complete workflows |
| **Environment** | Isolated/mocked | Partial real environment | Full production-like |
| **Data** | Minimal test vectors | Representative samples | Realistic datasets |
| **Duration** | Milliseconds | Seconds | Minutes to hours |
| **Purpose** | Correctness | Interface contracts | User requirements |
| **Failures** | Code bugs | Integration issues | System-level problems |

## **Conclusion**

System/E2E testing is essential for validating that your AES file encryption tool works correctly from the user's perspective. It catches issues that unit and integration tests miss, such as:

- Incorrect command-line argument parsing
- File permission problems
- Memory leaks in long-running operations
- Performance degradation with large files
- Error handling in real-world scenarios

The key is to **test what users actually do**, not what developers think they do. Focus on complete workflows, realistic data, and production-like environments while avoiding the common pitfall of testing implementation details rather than user-visible behavior.

For your AES tool, prioritize testing the most common user scenarios: encrypting/decrypting various file types, handling different key sizes and modes, error recovery, and performance with realistic file sizes.
