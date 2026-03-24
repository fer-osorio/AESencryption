// cli_config.hpp - Configuration structures for CLI
#ifndef CLI_CONFIG_HPP
#define CLI_CONFIG_HPP

#include "../../core-crypto/include/cipher.hpp"
#include <filesystem>
#include <stdexcept>
#include <string>
#include <unordered_map>

namespace CLIConfig {

// Dumb tokenizer: walks argv and populates a key→value map.
// No crypto-specific knowledge.
class ArgumentParser {
public:
    ArgumentParser(int argc, const char** argv);
    void parse();

    bool        has(const std::string& flag) const;
    std::string get(const std::string& flag) const;   // throws std::out_of_range if absent
    std::string getOr(const std::string& flag, const std::string& fallback) const;
    const char* program_name() const;

private:
    int          argc_;
    const char** argv_;
    std::unordered_map<std::string, std::string> options_;
};

// Abstract base: each concrete config subclass implements validate().
class BaseCryptoConfig {
public:
    virtual ~BaseCryptoConfig() = default;
    virtual bool validate(const ArgumentParser& parser) = 0;

    bool        is_valid = false;
    std::string error_message;
};

// Concrete config for generic file encryption tools.
class FileCryptoConfig : public BaseCryptoConfig {
public:
    enum class Operation { ENCRYPT, DECRYPT, GENERATE_KEY };

    bool validate(const ArgumentParser& parser) override;
    virtual void print_help(const ArgumentParser& parser) const;

    // Factory methods
    CipherFortis::Key                           create_key()     const;
    CipherFortis::Cipher::OperationMode         create_optmode() const;

    // Fields
    Operation                                        operation      = Operation::ENCRYPT;
    std::filesystem::path                            key_file, input_file, output_file, mode_file;
    CipherFortis::Key::LengthBits                   key_length     = CipherFortis::Key::LengthBits::_128;
    CipherFortis::Cipher::OperationMode::Identifier operation_mode = CipherFortis::Cipher::OperationMode::Identifier::CBC;
};

} // namespace CLIConfig

#endif  // CLI_CONFIG_HPP
