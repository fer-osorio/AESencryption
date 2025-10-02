// cli_config.hpp - Configuration structures for CLI
#ifndef CLI_CONFIG_HPP
#define CLI_CONFIG_HPP

#include "../../include/cipher.hpp"
#include <filesystem> // For path handling
#include <optional>
#include <stdexcept>

namespace CLI {

// Configuration structure - the integration point
struct CryptoConfig {
    enum class Operation {
        ENCRYPT,
        DECRYPT,
        GENERATE_KEY
    };

    Operation operation;
    std::filesystem::path key_file;
    std::filesystem::path input_file;
    std::filesystem::path output_file;

    // Optional parameters with defaults
    AESencryption::Key::LengthBits key_length = AESencryption::Key::LengthBits::_128;
    AESencryption::Cipher::OperationMode::Identifier operation_mode = AESencryption::Cipher::OperationMode::Identifier::CBC;

    // Validation flags
    bool is_valid = false;
    std::string error_message;

    // Validation method
    bool validate();

    // Convert to crypto objects - the integration point!
    // Consider: Throws std::runtime_error
    AESencryption::Key create_key() const;
};

// Argument parser - Component A
class ArgumentParser {
private:
    int argc;
    const char** argv;
    CryptoConfig config;

public:
    ArgumentParser(int argc_, const char** argv_);

    // Main parsing method
    CryptoConfig parse();
    CryptoConfig get_config() const;

private:
    void print_help() const;
};

} // namespace CLI

#endif