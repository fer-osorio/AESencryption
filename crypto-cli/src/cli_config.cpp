#include "../include/cli_config.hpp"
#include <iostream>

using namespace CLIConfig;

// ── ArgumentParser ────────────────────────────────────────────────────────────

ArgumentParser::ArgumentParser(int argc, const char** argv)
    : argc_(argc), argv_(argv) {}

void ArgumentParser::parse() {
    for (int i = 1; i < argc_; ++i) {
        std::string arg(argv_[i]);
        if (arg.size() < 2 || arg[0] != '-' || arg[1] != '-')
            continue;   // skip positional/non-flag tokens

        bool next_is_value = (i + 1 < argc_) &&
                             !(std::string(argv_[i + 1]).size() >= 2 &&
                               argv_[i + 1][0] == '-' && argv_[i + 1][1] == '-');
        if (next_is_value) {
            options_[arg] = argv_[++i];
        } else {
            options_[arg] = "";   // boolean flag — present but no value
        }
    }
}

bool ArgumentParser::has(const std::string& flag) const {
    return options_.count(flag) > 0;
}

std::string ArgumentParser::get(const std::string& flag) const {
    auto it = options_.find(flag);
    if (it == options_.end())
        throw std::out_of_range("Missing required flag: " + flag);
    return it->second;
}

std::string ArgumentParser::getOr(const std::string& flag,
                                   const std::string& fallback) const {
    auto it = options_.find(flag);
    return (it != options_.end()) ? it->second : fallback;
}

const char* ArgumentParser::program_name() const {
    return (argc_ > 0) ? argv_[0] : "";
}

// ── FileCryptoConfig ──────────────────────────────────────────────────────────

bool FileCryptoConfig::validate(const ArgumentParser& parser) {
    if (parser.has("--help")) {
        print_help(parser);
        is_valid = false;
        return false;
    }

    // Operation (last flag checked first so precedence matches intent)
    if      (parser.has("--generate-key")) operation = Operation::GENERATE_KEY;
    else if (parser.has("--decrypt"))      operation = Operation::DECRYPT;
    else if (parser.has("--encrypt"))      operation = Operation::ENCRYPT;
    // else: default is ENCRYPT

    // File paths
    key_file    = parser.getOr("--key",       "");
    input_file  = parser.getOr("--input",     "");
    output_file = parser.getOr("--output",    "");
    mode_file   = parser.getOr("--mode-data", "");

    // Operation mode
    std::string mode_str = parser.getOr("--mode", "");
    if (!mode_str.empty()) {
        if      (mode_str == "ECB") operation_mode = AESencryption::Cipher::OperationMode::Identifier::ECB;
        else if (mode_str == "CBC") operation_mode = AESencryption::Cipher::OperationMode::Identifier::CBC;
        else if (mode_str == "OFB") operation_mode = AESencryption::Cipher::OperationMode::Identifier::OFB;
        else if (mode_str == "CTR") operation_mode = AESencryption::Cipher::OperationMode::Identifier::CTR;
        else {
            error_message = "Invalid mode: " + mode_str + ". Use ECB, CBC, OFB, or CTR.";
            is_valid = false;
            return false;
        }
    }

    // Key length
    std::string kl_str = parser.getOr("--key-length", "");
    if (!kl_str.empty()) {
        try {
            int bits = std::stoi(kl_str);
            if      (bits == 128) key_length = AESencryption::Key::LengthBits::_128;
            else if (bits == 192) key_length = AESencryption::Key::LengthBits::_192;
            else if (bits == 256) key_length = AESencryption::Key::LengthBits::_256;
            else {
                error_message = "Invalid key length: " + kl_str + ". Use 128, 192, or 256.";
                is_valid = false;
                return false;
            }
        } catch (const std::exception&) {
            error_message = "Invalid key length: " + kl_str + ". Use 128, 192, or 256.";
            is_valid = false;
            return false;
        }
    }

    // Structural validation
    switch (operation) {
        case Operation::ENCRYPT:
        case Operation::DECRYPT:
            if (key_file.empty()) {
                error_message = "Key file is required for encryption/decryption";
                return false;
            }
            if (input_file.empty()) {
                error_message = "Input file is required";
                return false;
            }
            if (output_file.empty()) {
                error_message = "Output file is required";
                return false;
            }
            if (operation == Operation::DECRYPT) {
                if (mode_file.empty() &&
                    operation_mode != AESencryption::Cipher::OperationMode::Identifier::ECB) {
                    error_message = "Missing initial vector, nonce, counter or oder required data";
                    return false;
                }
            }
            break;
        case Operation::GENERATE_KEY:
            if (output_file.empty()) {
                error_message = "Output file is required for key generation";
                return false;
            }
            break;
    }

    is_valid = true;
    return true;
}

void FileCryptoConfig::print_help(const ArgumentParser& parser) const {
    const char* prog = parser.program_name();
    std::cout << prog << ". AES Encryption Tool\n\n"
              << "Usage:\n"
              << "\tEncryption\t"   << prog << " --encrypt --key <keyfile> --input <file> --output <file> [options]\n"
              << "\tDecryption\t"   << prog << " --decrypt --key <keyfile> --input <file> --output <file> --mode-data <file> [options]\n"
              << "\tKey Generation:\t" << prog << " --generate-key --key-length <bits> --output <file>\n\n"
              << "Options:\n"
              << "\t--key-length <bits>      Key length: 128, 192, or 256 (default: 128)\n"
              << "\t--mode <ECB|CBC|OFB|CTR> Operation mode (default: CBC)\n"
              << "\t--mode-data <file>       Required data for specific operation mode\n"
              << "\t--help                   Show this help message\n";
}

AESencryption::Key FileCryptoConfig::create_key() const {
    if (!is_valid)
        throw std::runtime_error("Cannot create key from invalid configuration");
    if (operation == Operation::GENERATE_KEY)
        return AESencryption::Key(key_length);
    try {
        return AESencryption::Key(key_file.c_str());
    } catch (const std::exception&) {
        throw;
    }
}

AESencryption::Cipher::OperationMode FileCryptoConfig::create_optmode() const {
    if (!is_valid)
        throw std::runtime_error("Cannot create operation mode object from invalid configuration");
    if (!mode_file.empty()) {
        try {
            return AESencryption::Cipher::OperationMode::loadFromFile(mode_file);
        } catch (const std::exception&) {
            throw;
        }
    }
    return AESencryption::Cipher::OperationMode(operation_mode);
}
