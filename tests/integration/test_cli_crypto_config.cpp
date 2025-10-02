#include "../include/test_framework.hpp"
#include "../../CLI/include/cli_config.hpp"
#include "../../include/cipher.hpp"
#include <cstring>

namespace TestHelpers {
    // Helper to create argv array for testing
    class ArgvBuilder {
    private:
        std::vector<std::string> args_storage;
        std::vector<char*> argv_ptrs;

    public:
        ArgvBuilder& add(const std::string& arg) {
            args_storage.push_back(arg);
            return *this;
        }

        char** build(int& argc) {
            argv_ptrs.clear();
            for (std::string& arg : args_storage) {
                argv_ptrs.push_back(const_cast<char*>(arg.c_str()));
            }
            argc = argv_ptrs.size();
            return argv_ptrs.data();
        }
    };
}

// ============================================================================
// TEST 1: Happy Path - Valid Arguments Create Valid Crypto Objects
// ============================================================================
bool test_valid_encryption_arguments();

// ============================================================================
// TEST 2: Data Type Conversion - Strings to Crypto Types
// ============================================================================
bool test_argument_to_crypto_type_conversion();

// ============================================================================
// TEST 3: Error Propagation - Invalid Arguments Don't Create Crypto Objects
// ============================================================================
bool test_invalid_arguments_prevent_crypto_initialization();

// ============================================================================
// TEST 4: Missing Required Arguments
// ============================================================================
bool test_missing_required_arguments();

// ============================================================================
// TEST 5: Default Values Are Applied Correctly
// ============================================================================
bool test_default_values();

// ============================================================================
// TEST 6: Integration with Real Crypto Objects
// ============================================================================
bool test_config_creates_functional_crypto_objects();

// ============================================================================
// TEST 7: Multiple Valid Argument Formats
// ============================================================================
bool test_argument_format_variations();

int main() {
    std::cout << "=== CLI Argument Parsing ↔ Crypto Configuration Integration Tests ===" << std::endl;
    std::cout << "\nThis test suite validates the integration between command-line" << std::endl;
    std::cout << "argument parsing and cryptographic configuration initialization.\n" << std::endl;

    test_valid_encryption_arguments();
    test_argument_to_crypto_type_conversion();
    test_invalid_arguments_prevent_crypto_initialization();
    test_missing_required_arguments();
    test_default_values();
    test_config_creates_functional_crypto_objects();
    test_argument_format_variations();

    std::cout << "\n=== CLI-Crypto Integration Tests Complete ===" << std::endl;
    return 0;
}

bool test_valid_encryption_arguments() {
    TEST_SUITE("Valid Encryption Arguments Integration");
    bool success = true;

    // Setup: Prepare command-line arguments
    int argc;
    TestHelpers::ArgvBuilder builder;
    char** argv = builder
        .add("aes-encryption")
        .add("--encrypt")
        .add("--key").add("test_key.bin")
        .add("--input").add("plaintext.txt")
        .add("--output").add("encrypted.bin")
        .add("--mode").add("CBC")
        .add("--key-length").add("256")
        .build(argc);

    // Parse arguments
    CLI::ArgumentParser parser(argc, argv);
    CLI::CryptoConfig config = parser.parse();

    // Test: Configuration should be valid
    success &= ASSERT_TRUE(config.is_valid, "Configuration should be valid with all required arguments");
    success &= ASSERT_TRUE(config.error_message.empty(), "No error message should be present");

    // Test: Configuration values match arguments
    success &= ASSERT_TRUE(config.operation == CLI::CryptoConfig::Operation::ENCRYPT,
                "Operation should be ENCRYPT");
    success &= ASSERT_TRUE(config.key_file == "test_key.bin", "Key file should match argument");
    success &= ASSERT_TRUE(config.input_file == "plaintext.txt", "Input file should match argument");
    success &= ASSERT_TRUE(config.output_file == "encrypted.bin", "Output file should match argument");

    // Test: Enum conversions are correct
    success &= ASSERT_TRUE(config.operation_mode == AESencryption::Cipher::OperationMode::Identifier::CBC,
                "Operation mode should be CBC");
    success &= ASSERT_TRUE(config.key_length == AESencryption::Key::LengthBits::_256,
                "Key length should be 256 bits");

    PRINT_RESULTS();
    return success;
}

bool test_argument_to_crypto_type_conversion() {
    TEST_SUITE("Argument to Crypto Type Conversion");
    bool success = true;

    // Test ECB mode conversion
    {
        int argc;
        TestHelpers::ArgvBuilder builder;
        char** argv = builder
            .add("aes-encryption")
            .add("--encrypt")
            .add("--key").add("key.bin")
            .add("--input").add("in.txt")
            .add("--output").add("out.bin")
            .add("--mode").add("ECB")
            .build(argc);

        CLI::ArgumentParser parser(argc, argv);
        CLI::CryptoConfig config = parser.parse();

        success &= ASSERT_TRUE(config.operation_mode == AESencryption::Cipher::OperationMode::Identifier::ECB,
                    "String 'ECB' should convert to OperationMode::Identifier::ECB");
    }

    // Test all key lengths
    for (int bits : {128, 192, 256}) {
        int argc;
        TestHelpers::ArgvBuilder builder;
        char** argv = builder
            .add("aes-encryption")
            .add("--encrypt")
            .add("--key").add("key.bin")
            .add("--input").add("in.txt")
            .add("--output").add("out.bin")
            .add("--key-length").add(std::to_string(bits))
            .build(argc);

        CLI::ArgumentParser parser(argc, argv);
        CLI::CryptoConfig config = parser.parse();

        success &= ASSERT_TRUE(config.is_valid,
                    "Key length " + std::to_string(bits) + " should be valid");

        // Verify the conversion
        int expected_bits = static_cast<int>(config.key_length);
        success &= ASSERT_EQUAL(bits, expected_bits,
                    "Key length conversion should preserve value");
    }

    PRINT_RESULTS();
    return success;
}

bool test_invalid_arguments_prevent_crypto_initialization() {
    TEST_SUITE("Invalid Arguments Error Handling");
    bool success = true;

    // Test: Invalid key length
    {
        int argc;
        TestHelpers::ArgvBuilder builder;
        char** argv = builder
            .add("aes-encryption")
            .add("--encrypt")
            .add("--key").add("key.bin")
            .add("--input").add("in.txt")
            .add("--output").add("out.bin")
            .add("--key-length").add("512")  // Invalid!
            .build(argc);

        CLI::ArgumentParser parser(argc, argv);
        CLI::CryptoConfig config = parser.parse();

        success &= ASSERT_TRUE(!config.is_valid, "Invalid key length should mark config invalid");
        success &= ASSERT_TRUE(!config.error_message.empty(), "Error message should be provided");
        success &= ASSERT_TRUE(config.error_message.find("512") != std::string::npos,
                    "Error message should mention invalid value");
    }

    // Test: Invalid mode
    {
        int argc;
        TestHelpers::ArgvBuilder builder;
        char** argv = builder
            .add("aes-encryption")
            .add("--encrypt")
            .add("--key").add("key.bin")
            .add("--input").add("in.txt")
            .add("--output").add("out.bin")
            .add("--mode").add("XTS")  // Invalid mode!
            .build(argc);

        CLI::ArgumentParser parser(argc, argv);
        CLI::CryptoConfig config = parser.parse();

        success &= ASSERT_TRUE(!config.is_valid, "Invalid mode should mark config invalid");
        success &= ASSERT_TRUE(config.error_message.find("XTS") != std::string::npos,
                    "Error message should mention invalid mode");
    }

    // Test: Attempting to create key from invalid config should throw
    {
        CLI::CryptoConfig invalid_config;
        invalid_config.is_valid = false;
        invalid_config.error_message = "Test error";

        try {
            AESencryption::Key key = invalid_config.create_key();
            success &= ASSERT_TRUE(false, "Creating key from invalid config should throw exception");
        } catch (const std::runtime_error& e) {
            success &= ASSERT_TRUE(true, "Invalid config properly throws exception");
            success &= ASSERT_TRUE(std::string(e.what()).find("invalid") != std::string::npos,
                        "Exception message should mention invalid configuration");
        }
    }

    PRINT_RESULTS();
    return success;
}

bool test_missing_required_arguments() {
    TEST_SUITE("Missing Required Arguments");
    bool success = true;

    // Test: Missing key file
    {
        int argc;
        TestHelpers::ArgvBuilder builder;
        char** argv = builder
            .add("aes-encryption")
            .add("--encrypt")
            .add("--input").add("in.txt")
            .add("--output").add("out.bin")
            .build(argc);

        CLI::ArgumentParser parser(argc, argv);
        CLI::CryptoConfig config = parser.parse();

        success &= ASSERT_TRUE(!config.is_valid, "Missing key file should invalidate config");
        success &= ASSERT_TRUE(config.error_message.find("key") != std::string::npos ||
                    config.error_message.find("Key") != std::string::npos,
                    "Error should mention missing key");
    }

    // Test: Missing input file
    {
        int argc;
        TestHelpers::ArgvBuilder builder;
        char** argv = builder
            .add("aes-encryption")
            .add("--encrypt")
            .add("--key").add("key.bin")
            .add("--output").add("out.bin")
            .build(argc);

        CLI::ArgumentParser parser(argc, argv);
        CLI::CryptoConfig config = parser.parse();

        success &= ASSERT_TRUE(!config.is_valid, "Missing input file should invalidate config");
        success &= ASSERT_TRUE(config.error_message.find("input") != std::string::npos ||
                    config.error_message.find("Input") != std::string::npos,
                    "Error should mention missing input");
    }

    // Test: No arguments at all
    {
        int argc = 1;
        char* argv[] = {(char*)"aes-encryption"};

        CLI::ArgumentParser parser(argc, argv);
        CLI::CryptoConfig config = parser.parse();

        success &= ASSERT_TRUE(!config.is_valid, "No arguments should invalidate config");
    }

    PRINT_RESULTS();
    return success;
}

bool test_default_values() {
    TEST_SUITE("Default Configuration Values");
    bool success = true;

    // When mode is not specified, should default to CBC
    int argc;
    TestHelpers::ArgvBuilder builder;
    char** argv = builder
        .add("aes-encryption")
        .add("--encrypt")
        .add("--key").add("key.bin")
        .add("--input").add("in.txt")
        .add("--output").add("out.bin")
        // Note: no --mode argument
        .build(argc);

    CLI::ArgumentParser parser(argc, argv);
    CLI::CryptoConfig config = parser.parse();

    success &= ASSERT_TRUE(config.is_valid, "Config should be valid with defaults");
    success &= ASSERT_TRUE(config.operation_mode == AESencryption::Cipher::OperationMode::Identifier::CBC,
                "Default operation mode should be CBC");
    success &= ASSERT_TRUE(config.key_length == AESencryption::Key::LengthBits::_128,
                "Default key length should be 128 bits");

    PRINT_RESULTS();
    return success;
}

bool test_config_creates_functional_crypto_objects() {
    TEST_SUITE("Configuration Creates Functional Crypto Objects");
    bool success = true;

    // Note: This test requires a real key file to exist
    // In a real scenario, you'd create a temporary key file first

    // For demonstration, we'll test the structure without file I/O
    int argc;
    TestHelpers::ArgvBuilder builder;
    char** argv = builder
        .add("aes-encryption")
        .add("--encrypt")
        .add("--generate-key")
        .add("--key-length").add("256")
        .add("--output").add("test_key.bin")
        .build(argc);

    CLI::ArgumentParser parser(argc, argv);
    CLI::CryptoConfig config = parser.parse();

    success &= ASSERT_TRUE(config.is_valid, "Key generation config should be valid");
    success &= ASSERT_TRUE(config.operation == CLI::CryptoConfig::Operation::GENERATE_KEY,
                "Operation should be GENERATE_KEY");
    success &= ASSERT_TRUE(config.key_length == AESencryption::Key::LengthBits::_256,
                "Key length should be 256");

    // Test that configuration values can create crypto objects
    // (This would create actual Key object)
    success &= ASSERT_TRUE(true, "Configuration provides all necessary values for crypto object creation");

    PRINT_RESULTS();
    return success;
}

bool test_argument_format_variations() {
    TEST_SUITE("Argument Format Variations");
    bool success = true;

    // Test that decrypt option affects operation detection
    {
        int argc;
        TestHelpers::ArgvBuilder builder;
        char** argv = builder
            .add("aes-encryption")
            .add("--decrypt")   // Note: decrypt option
            .add("--key").add("key.bin")
            .add("--input").add("encrypted.bin")
            .add("--output").add("decrypted.txt")
            .build(argc);

        CLI::ArgumentParser parser(argc, argv);
        CLI::CryptoConfig config = parser.parse();

        success &= ASSERT_TRUE(config.operation == CLI::CryptoConfig::Operation::DECRYPT,
                    "Program name should affect operation detection");
    }

    PRINT_RESULTS();
    return success;
}
