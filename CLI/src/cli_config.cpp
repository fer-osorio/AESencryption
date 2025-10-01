#include "../include/cli_config.hpp"

using namespace CLI;

bool CryptoConfig::validate() {
    // Check required fields based on operation
    if (this->operation == Operation::ENCRYPT || this->operation == Operation::DECRYPT) {
        if (this->key_file.empty()) {
            this->error_message = "Key file is required for encryption/decryption";
            return false;
        }
        if (this->input_file.empty()) {
            this->error_message = "Input file is required";
            return false;
        }
        if (this->output_file.empty()) {
            this->error_message = "Output file is required";
            return false;
        }
    }
    if (this->operation == Operation::GENERATE_KEY) {
        if (this->output_file.empty()) {
            this->error_message = "Output file is required for key generation";
            return false;
        }
    }
    this->is_valid = true;
    return true;
}

AESencryption::Key CryptoConfig::create_key() const {
    if (!this->is_valid) {
        throw std::runtime_error("Cannot create key from invalid configuration");
    }
    if (this->operation == Operation::GENERATE_KEY) {
        // Generate new random key (constructor to be implemented)
        return AESencryption::Key(this->key_length);
    } else {
        // Load key from file
        return AESencryption::Key(this->key_file.c_str());
    }
}

CryptoConfig ArgumentParser::parse() {
    if (argc < 2) {
        config.error_message = "No arguments provided. Use --help for usage information.";
        config.is_valid = false;
        return config;
    }

    // Determine operation from program name or first argument
    std::string program_name(argv[0]);
    if (program_name.find("decrypt") != std::string::npos) {
        config.operation = CryptoConfig::Operation::DECRYPT;
    } else if (program_name.find("encrypt") != std::string::npos) {
        config.operation = CryptoConfig::Operation::ENCRYPT;
    }

    // Parse arguments
    for (int i = 1; i < argc; i++) {
        std::string arg(argv[i]);

        if (arg == "--key" && i + 1 < argc) {
            config.key_file = argv[++i];
        }
        else if (arg == "--input" && i + 1 < argc) {
            config.input_file = argv[++i];
        }
        else if (arg == "--output" && i + 1 < argc) {
            config.output_file = argv[++i];
        }
        else if (arg == "--mode" && i + 1 < argc) {
            std::string mode(argv[++i]);
        if (mode == "ECB") {
                config.operation_mode = AESencryption::Cipher::OperationMode::Identifier::ECB;
            } else if (mode == "CBC") {
                config.operation_mode = AESencryption::Cipher::OperationMode::Identifier::CBC;
            } else {
                config.error_message = "Invalid mode: " + mode + ". Use ECB or CBC.";
                config.is_valid = false;
                return config;
            }
        }
        else if (arg == "--key-length" && i + 1 < argc) {
            int bits = std::stoi(argv[++i]);
            if (bits == 128) {
                config.key_length = AESencryption::Key::LengthBits::_128;
            } else if (bits == 192) {
                config.key_length = AESencryption::Key::LengthBits::_192;
            } else if (bits == 256) {
                config.key_length = AESencryption::Key::LengthBits::_256;
                } else {
                config.error_message = "Invalid key length: " + std::to_string(bits) +
                                     ". Use 128, 192, or 256.";
                config.is_valid = false;
                return config;
            }
        }
        else if (arg == "--generate-key") {
            config.operation = CryptoConfig::Operation::GENERATE_KEY;
        }
        else if (arg == "--help") {
            print_help();
            config.is_valid = false;
            return config;
        }
        else {
            config.error_message = "Unknown argument: " + arg;
            config.is_valid = false;
            return config;
        }
    }

    // Validate the configuration
    config.validate();
    return config;
}

CryptoConfig ArgumentParser::get_config() const {
    return this->config;
}

void ArgumentParser::print_help() const{
    std::cout << "AES Encryption Tool\n\n"
              << "Usage:\n"
              << "  Encryption: aes-encrypt --key <keyfile> --input <file> --output <file> [options]\n"
              << "  Decryption: aes-decrypt --key <keyfile> --input <file> --output <file> [options]\n"
              << "  Key Generation: aes-encrypt --generate-key --key-length <bits> --output <file>\n\n"
              << "Options:\n"
              << "  --mode <ECB|CBC>         Operation mode (default: CBC)\n"
              << "  --key-length <bits>      Key length: 128, 192, or 256 (default: 128)\n"
              << "  --help                   Show this help message\n";
}
