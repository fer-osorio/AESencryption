#include <gtest/gtest.h>
#include "../../cli-tools/include/cli_config.hpp"
#include "../../core-crypto/include/cipher.hpp"

namespace TestHelpers {
    class ArgvBuilder {
    private:
        std::vector<std::string> args_storage;
        std::vector<const char*> argv_ptrs;

    public:
        ArgvBuilder& add(const std::string& arg) {
            args_storage.push_back(arg);
            return *this;
        }

        const char** build(int& argc) {
            argv_ptrs.clear();
            for (std::string& arg : args_storage) {
                argv_ptrs.push_back(const_cast<char*>(arg.c_str()));
            }
            argc = argv_ptrs.size();
            return argv_ptrs.data();
        }
    };
}

TEST(CliCryptoConfig, ValidEncryptionArguments) {
    int argc;
    TestHelpers::ArgvBuilder builder;
    const char** argv = builder
        .add("aes-encryption")
        .add("--encrypt")
        .add("--key").add("test_key.bin")
        .add("--input").add("plaintext.txt")
        .add("--output").add("encrypted.bin")
        .add("--mode").add("CBC")
        .add("--key-length").add("256")
        .build(argc);

    CLIConfig::ArgumentParser parser(argc, argv);
    parser.parse();
    CLIConfig::FileCryptoConfig config;
    config.validate(parser);

    EXPECT_TRUE(config.is_valid) << "Configuration should be valid with all required arguments";
    EXPECT_TRUE(config.error_message.empty()) << "No error message should be present";
    EXPECT_TRUE(config.operation == CLIConfig::FileCryptoConfig::Operation::ENCRYPT)
        << "Operation should be ENCRYPT";
    EXPECT_TRUE(config.key_file == "test_key.bin") << "Key file should match argument";
    EXPECT_TRUE(config.input_file == "plaintext.txt") << "Input file should match argument";
    EXPECT_TRUE(config.output_file == "encrypted.bin") << "Output file should match argument";
    EXPECT_TRUE(config.operation_mode == CipherFortis::Cipher::OperationMode::Identifier::CBC)
        << "Operation mode should be CBC";
    EXPECT_TRUE(config.key_length == CipherFortis::Key::LengthBits::_256)
        << "Key length should be 256 bits";
}

TEST(CliCryptoConfig, ArgumentToCryptoTypeConversion) {
    // ECB mode conversion
    {
        int argc;
        TestHelpers::ArgvBuilder builder;
        const char** argv = builder
            .add("aes-encryption")
            .add("--encrypt")
            .add("--key").add("key.bin")
            .add("--input").add("in.txt")
            .add("--output").add("out.bin")
            .add("--mode").add("ECB")
            .build(argc);

        CLIConfig::ArgumentParser parser(argc, argv);
        parser.parse();
        CLIConfig::FileCryptoConfig config;
        config.validate(parser);

        EXPECT_TRUE(config.operation_mode == CipherFortis::Cipher::OperationMode::Identifier::ECB)
            << "String 'ECB' should convert to OperationMode::Identifier::ECB";
    }

    // All key lengths
    for (int bits : {128, 192, 256}) {
        int argc;
        TestHelpers::ArgvBuilder builder;
        const char** argv = builder
            .add("aes-encryption")
            .add("--encrypt")
            .add("--key").add("key.bin")
            .add("--input").add("in.txt")
            .add("--output").add("out.bin")
            .add("--key-length").add(std::to_string(bits))
            .build(argc);

        CLIConfig::ArgumentParser parser(argc, argv);
        parser.parse();
        CLIConfig::FileCryptoConfig config;
        config.validate(parser);

        EXPECT_TRUE(config.is_valid)
            << "Key length " + std::to_string(bits) + " should be valid";

        int expected_bits = static_cast<int>(config.key_length);
        EXPECT_EQ(bits, expected_bits) << "Key length conversion should preserve value";
    }
}

TEST(CliCryptoConfig, InvalidArgumentsPreventCryptoInit) {
    // Invalid key length
    {
        int argc;
        TestHelpers::ArgvBuilder builder;
        const char** argv = builder
            .add("aes-encryption")
            .add("--encrypt")
            .add("--key").add("key.bin")
            .add("--input").add("in.txt")
            .add("--output").add("out.bin")
            .add("--key-length").add("512")
            .build(argc);

        CLIConfig::ArgumentParser parser(argc, argv);
        parser.parse();
        CLIConfig::FileCryptoConfig config;
        config.validate(parser);

        EXPECT_TRUE(!config.is_valid) << "Invalid key length should mark config invalid";
        EXPECT_TRUE(!config.error_message.empty()) << "Error message should be provided";
        EXPECT_NE(config.error_message.find("512"), std::string::npos)
            << "Error message should mention invalid value";
    }

    // Invalid mode
    {
        int argc;
        TestHelpers::ArgvBuilder builder;
        const char** argv = builder
            .add("aes-encryption")
            .add("--encrypt")
            .add("--key").add("key.bin")
            .add("--input").add("in.txt")
            .add("--output").add("out.bin")
            .add("--mode").add("XTS")
            .build(argc);

        CLIConfig::ArgumentParser parser(argc, argv);
        parser.parse();
        CLIConfig::FileCryptoConfig config;
        config.validate(parser);

        EXPECT_TRUE(!config.is_valid) << "Invalid mode should mark config invalid";
        EXPECT_NE(config.error_message.find("XTS"), std::string::npos)
            << "Error message should mention invalid mode";
    }

    // Creating key from invalid config should throw
    {
        CLIConfig::FileCryptoConfig invalid_config;
        invalid_config.is_valid = false;
        invalid_config.error_message = "Test error";

        try {
            CipherFortis::Key key = invalid_config.create_key();
            FAIL() << "Creating key from invalid config should throw exception";
        } catch (const std::runtime_error& e) {
            EXPECT_NE(std::string(e.what()).find("invalid"), std::string::npos)
                << "Exception message should mention invalid configuration";
        }
    }
}

TEST(CliCryptoConfig, MissingRequiredArguments) {
    // Missing key file
    {
        int argc;
        TestHelpers::ArgvBuilder builder;
        const char** argv = builder
            .add("aes-encryption")
            .add("--encrypt")
            .add("--input").add("in.txt")
            .add("--output").add("out.bin")
            .build(argc);

        CLIConfig::ArgumentParser parser(argc, argv);
        parser.parse();
        CLIConfig::FileCryptoConfig config;
        config.validate(parser);

        EXPECT_TRUE(!config.is_valid) << "Missing key file should invalidate config";
        EXPECT_TRUE(config.error_message.find("key") != std::string::npos ||
                    config.error_message.find("Key") != std::string::npos)
            << "Error should mention missing key";
    }

    // Missing input file
    {
        int argc;
        TestHelpers::ArgvBuilder builder;
        const char** argv = builder
            .add("aes-encryption")
            .add("--encrypt")
            .add("--key").add("key.bin")
            .add("--output").add("out.bin")
            .build(argc);

        CLIConfig::ArgumentParser parser(argc, argv);
        parser.parse();
        CLIConfig::FileCryptoConfig config;
        config.validate(parser);

        EXPECT_TRUE(!config.is_valid) << "Missing input file should invalidate config";
        EXPECT_TRUE(config.error_message.find("input") != std::string::npos ||
                    config.error_message.find("Input") != std::string::npos)
            << "Error should mention missing input";
    }

    // No arguments at all
    {
        int argc = 1;
        const char* argv[] = {"aes-encryption"};

        CLIConfig::ArgumentParser parser(argc, argv);
        parser.parse();
        CLIConfig::FileCryptoConfig config;
        config.validate(parser);

        EXPECT_TRUE(!config.is_valid) << "No arguments should invalidate config";
    }
}

TEST(CliCryptoConfig, DefaultValues) {
    int argc;
    TestHelpers::ArgvBuilder builder;
    const char** argv = builder
        .add("aes-encryption")
        .add("--encrypt")
        .add("--key").add("key.bin")
        .add("--input").add("in.txt")
        .add("--output").add("out.bin")
        .build(argc);

    CLIConfig::ArgumentParser parser(argc, argv);
    parser.parse();
    CLIConfig::FileCryptoConfig config;
    config.validate(parser);

    EXPECT_TRUE(config.is_valid) << "Config should be valid with defaults";
    EXPECT_TRUE(config.operation_mode == CipherFortis::Cipher::OperationMode::Identifier::CBC)
        << "Default operation mode should be CBC";
    EXPECT_TRUE(config.key_length == CipherFortis::Key::LengthBits::_128)
        << "Default key length should be 128 bits";
}

TEST(CliCryptoConfig, ConfigCreatesFunctionalCryptoObjects) {
    int argc;
    TestHelpers::ArgvBuilder builder;
    const char** argv = builder
        .add("aes-encryption")
        .add("--encrypt")
        .add("--generate-key")
        .add("--key-length").add("256")
        .add("--output").add("test_key.bin")
        .build(argc);

    CLIConfig::ArgumentParser parser(argc, argv);
    parser.parse();
    CLIConfig::FileCryptoConfig config;
    config.validate(parser);

    EXPECT_TRUE(config.is_valid) << "Key generation config should be valid";
    EXPECT_TRUE(config.operation == CLIConfig::FileCryptoConfig::Operation::GENERATE_KEY)
        << "Operation should be GENERATE_KEY";
    EXPECT_TRUE(config.key_length == CipherFortis::Key::LengthBits::_256)
        << "Key length should be 256";
}

TEST(CliCryptoConfig, ArgumentFormatVariations) {
    int argc;
    TestHelpers::ArgvBuilder builder;
    const char** argv = builder
        .add("aes-encryption")
        .add("--decrypt")
        .add("--key").add("key.bin")
        .add("--input").add("encrypted.bin")
        .add("--output").add("decrypted.txt")
        .build(argc);

    CLIConfig::ArgumentParser parser(argc, argv);
    parser.parse();
    CLIConfig::FileCryptoConfig config;
    config.validate(parser);

    EXPECT_TRUE(config.operation == CLIConfig::FileCryptoConfig::Operation::DECRYPT)
        << "Program option --decrypt should affect operation detection";
}
