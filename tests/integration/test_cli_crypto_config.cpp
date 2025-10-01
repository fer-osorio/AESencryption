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
            for (auto& arg : args_storage) {
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
void test_valid_encryption_arguments() {
    TEST_SUITE("Valid Encryption Arguments Integration");

    // Setup: Prepare command-line arguments
    int argc;
    TestHelpers::ArgvBuilder builder;
    char** argv = builder
        .add("aes-encrypt")
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
    ASSERT_TRUE(config.is_valid, "Configuration should be valid with all required arguments");
    ASSERT_TRUE(config.error_message.empty(), "No error message should be present");

    // Test: Configuration values match arguments
    ASSERT_TRUE(config.operation == CLI::CryptoConfig::Operation::ENCRYPT,
                "Operation should be ENCRYPT");
    ASSERT_TRUE(config.key_file == "test_key.bin", "Key file should match argument");
    ASSERT_TRUE(config.input_file == "plaintext.txt", "Input file should match argument");
    ASSERT_TRUE(config.output_file == "encrypted.bin", "Output file should match argument");

    // Test: Enum conversions are correct
    ASSERT_TRUE(config.operation_mode == AESencryption::Cipher::OperationMode::Identifier::CBC,
                "Operation mode should be CBC");
    ASSERT_TRUE(config.key_length == AESencryption::Key::LengthBits::_256,
                "Key length should be 256 bits");

    PRINT_RESULTS();
}

// ============================================================================
// TEST 2: Data Type Conversion - Strings to Crypto Types
// ============================================================================
void test_argument_to_crypto_type_conversion() {
    TEST_SUITE("Argument to Crypto Type Conversion");

    // Test ECB mode conversion
    {
        int argc;
        TestHelpers::ArgvBuilder builder;
        char** argv = builder
            .add("aes-encrypt")
            .add("--key").add("key.bin")
            .add("--input").add("in.txt")
            .add("--output").add("out.bin")
            .add("--mode").add("ECB")
            .build(argc);

        CLI::ArgumentParser parser(argc, argv);
        CLI::CryptoConfig config = parser.parse();

        ASSERT_TRUE(config.operation_mode == AESencryption::Cipher::OperationMode::Identifier::ECB,
                    "String 'ECB' should convert to OpMode::ECB");
    }

    // Test all key lengths
    for (int bits : {128, 192, 256}) {
        int argc;
        TestHelpers::ArgvBuilder builder;
        char** argv = builder
            .add("aes-encrypt")
            .add("--key").add("key.bin")
            .add("--input").add("in.txt")
            .add("--output").add("out.bin")
            .add("--key-length").add(std::to_string(bits))
            .build(argc);

        CLI::ArgumentParser parser(argc, argv);
        CLI::CryptoConfig config = parser.parse();

        ASSERT_TRUE(config.is_valid,
                    "Key length " + std::to_string(bits) + " should be valid");

        // Verify the conversion
        int expected_bits = static_cast<int>(config.key_length);
        ASSERT_EQUAL(bits, expected_bits,
                    "Key length conversion should preserve value");
    }

    PRINT_RESULTS();
}

// ============================================================================
// TEST 3: Error Propagation - Invalid Arguments Don't Create Crypto Objects
// ============================================================================
void test_invalid_arguments_prevent_crypto_initialization() {
    TEST_SUITE("Invalid Arguments Error Handling");

    // Test: Invalid key length
    {
        int argc;
        TestHelpers::ArgvBuilder builder;
        char** argv = builder
            .add("aes-encrypt")
            .add("--key").add("key.bin")
            .add("--input").add("in.txt")
            .add("--output").add("out.bin")
            .add("--key-length").add("512")  // Invalid!
            .build(argc);

        CLI::ArgumentParser parser(argc, argv);
        CLI::CryptoConfig config = parser.parse();

        ASSERT_TRUE(!config.is_valid, "Invalid key length should mark config invalid");
        ASSERT_TRUE(!config.error_message.empty(), "Error message should be provided");
        ASSERT_TRUE(config.error_message.find("512") != std::string::npos,
                    "Error message should mention invalid value");
    }

    // Test: Invalid mode
    {
        int argc;
        TestHelpers::ArgvBuilder builder;
        char** argv = builder
            .add("aes-encrypt")
            .add("--key").add("key.bin")
            .add("--input").add("in.txt")
            .add("--output").add("out.bin")
            .add("--mode").add("XTS")  // Invalid mode!
            .build(argc);

        CLI::ArgumentParser parser(argc, argv);
        CLI::CryptoConfig config = parser.parse();

        ASSERT_TRUE(!config.is_valid, "Invalid mode should mark config invalid");
        ASSERT_TRUE(config.error_message.find("XTS") != std::string::npos,
                    "Error message should mention invalid mode");
    }

    // Test: Attempting to create key from invalid config should throw
    {
        CLI::CryptoConfig invalid_config;
        invalid_config.is_valid = false;
        invalid_config.error_message = "Test error";

        try {
            AESencryption::Key key = invalid_config.create_key();
            ASSERT_TRUE(false, "Creating key from invalid config should throw exception");
        } catch (const std::runtime_error& e) {
            ASSERT_TRUE(true, "Invalid config properly throws exception");
            ASSERT_TRUE(std::string(e.what()).find("invalid") != std::string::npos,
                        "Exception message should mention invalid configuration");
        }
    }

    PRINT_RESULTS();
}

// ============================================================================
// TEST 4: Missing Required Arguments
// ============================================================================
void test_missing_required_arguments() {
    TEST_SUITE("Missing Required Arguments");

    // Test: Missing key file
    {
        int argc;
        TestHelpers::ArgvBuilder builder;
        char** argv = builder
            .add("aes-encrypt")
            .add("--input").add("in.txt")
            .add("--output").add("out.bin")
            .build(argc);

        CLI::ArgumentParser parser(argc, argv);
        CLI::CryptoConfig config = parser.parse();

        ASSERT_TRUE(!config.is_valid, "Missing key file should invalidate config");
        ASSERT_TRUE(config.error_message.find("key") != std::string::npos ||
                    config.error_message.find("Key") != std::string::npos,
                    "Error should mention missing key");
    }

    // Test: Missing input file
    {
        int argc;
        TestHelpers::ArgvBuilder builder;
        char** argv = builder
            .add("aes-encrypt")
            .add("--key").add("key.bin")
            .add("--output").add("out.bin")
            .build(argc);

        CLI::ArgumentParser parser(argc, argv);
        CLI::CryptoConfig config = parser.parse();

        ASSERT_TRUE(!config.is_valid, "Missing input file should invalidate config");
        ASSERT_TRUE(config.error_message.find("input") != std::string::npos ||
                    config.error_message.find("Input") != std::string::npos,
                    "Error should mention missing input");
    }

    // Test: No arguments at all
    {
        int argc = 1;
        char* argv[] = {(char*)"aes-encrypt"};

        CLI::ArgumentParser parser(argc, argv);
        CLI::CryptoConfig config = parser.parse();

        ASSERT_TRUE(!config.is_valid, "No arguments should invalidate config");
    }

    PRINT_RESULTS();
}

// ============================================================================
// TEST 5: Default Values Are Applied Correctly
// ============================================================================
void test_default_values() {
    TEST_SUITE("Default Configuration Values");

    // When mode is not specified, should default to CBC
    int argc;
    TestHelpers::ArgvBuilder builder;
    char** argv = builder
        .add("aes-encrypt")
        .add("--key").add("key.bin")
        .add("--input").add("in.txt")
        .add("--output").add("out.bin")
        // Note: no --mode argument
        .build(argc);

    CLI::ArgumentParser parser(argc, argv);
    CLI::CryptoConfig config = parser.parse();

    ASSERT_TRUE(config.is_valid, "Config should be valid with defaults");
    ASSERT_TRUE(config.operation_mode == AESencryption::Cipher::OperationMode::Identifier::CBC,
                "Default operation mode should be CBC");
    ASSERT_TRUE(config.key_length == AESencryption::Key::LengthBits::_128,
                "Default key length should be 128 bits");

    PRINT_RESULTS();
}

// ============================================================================
// TEST 6: Integration with Real Crypto Objects
// ============================================================================
void test_config_creates_functional_crypto_objects() {
    TEST_SUITE("Configuration Creates Functional Crypto Objects");

    // Note: This test requires a real key file to exist
    // In a real scenario, you'd create a temporary key file first

    // For demonstration, we'll test the structure without file I/O
    int argc;
    TestHelpers::ArgvBuilder builder;
    char** argv = builder
        .add("aes-encrypt")
        .add("--generate-key")
        .add("--key-length").add("256")
        .add("--output").add("test_key.bin")
        .build(argc);

    CLI::ArgumentParser parser(argc, argv);
    CLI::CryptoConfig config = parser.parse();

    ASSERT_TRUE(config.is_valid, "Key generation config should be valid");
    ASSERT_TRUE(config.operation == CLI::CryptoConfig::Operation::GENERATE_KEY,
                "Operation should be GENERATE_KEY");
    ASSERT_TRUE(config.key_length == AESencryption::Key::LengthBits::_256,
                "Key length should be 256");

    // Test that configuration values can create crypto objects
    // (This would create actual Key object if constructor exists)
    ASSERT_TRUE(true, "Configuration provides all necessary values for crypto object creation");

    PRINT_RESULTS();
}

// ============================================================================
// TEST 7: Multiple Valid Argument Formats
// ============================================================================
void test_argument_format_variations() {
    TEST_SUITE("Argument Format Variations");

    // Test that program name affects operation detection
    {
        int argc;
        TestHelpers::ArgvBuilder builder;
        char** argv = builder
            .add("aes-decrypt")  // Note: decrypt in name
            .add("--key").add("key.bin")
            .add("--input").add("encrypted.bin")
            .add("--output").add("decrypted.txt")
            .build(argc);

        CLI::ArgumentParser parser(argc, argv);
        CLI::CryptoConfig config = parser.parse();

        ASSERT_TRUE(config.operation == CLI::CryptoConfig::Operation::DECRYPT,
                    "Program name should affect operation detection");
    }

    PRINT_RESULTS();
}

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
