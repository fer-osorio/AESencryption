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
        try{
            return AESencryption::Key(this->key_file.c_str());
        } catch(const std::exception& exp){
            throw;
        }
    }
}

ArgumentParser::ArgumentParser(int argc_, const char** argv_) : argc(argc_), argv(argv_) {}

CryptoConfig ArgumentParser::parse() {
    if (argc < 2) {
        this->config.error_message = "No arguments provided. Use --help for usage information.";
        this->config.is_valid = false;
        return this->config;
    }

    // Parse arguments
    for (int i = 1; i < argc; i++) {
        std::string arg(argv[i]);

        // Options that require an additional argument
        if (arg == "--key" && i + 1 < argc) {
            this->config.key_file = argv[++i];
        }
        else if (arg == "--input" && i + 1 < argc) {
            this->config.input_file = argv[++i];
        }
        else if (arg == "--output" && i + 1 < argc) {
            this->config.output_file = argv[++i];
        }
        else if (arg == "--mode" && i + 1 < argc) {
            std::string mode(argv[++i]);
        if (mode == "ECB") {
                this->config.operation_mode = AESencryption::Cipher::OperationMode::Identifier::ECB;
            } else if (mode == "CBC") {
                this->config.operation_mode = AESencryption::Cipher::OperationMode::Identifier::CBC;
            } else {
                this->config.error_message = "Invalid mode: " + mode + ". Use ECB or CBC.";
                this->config.is_valid = false;
                return this->config;
            }
        }
        else if (arg == "--key-length" && i + 1 < argc) {
            int bits = std::stoi(argv[++i]);
            if (bits == 128) {
                this->config.key_length = AESencryption::Key::LengthBits::_128;
            } else if (bits == 192) {
                this->config.key_length = AESencryption::Key::LengthBits::_192;
            } else if (bits == 256) {
                this->config.key_length = AESencryption::Key::LengthBits::_256;
                } else {
                this->config.error_message = "Invalid key length: " + std::to_string(bits) +
                                     ". Use 128, 192, or 256.";
                this->config.is_valid = false;
                return this->config;
            }
        }   // Options that do not require an additional argument
        else if (arg == "--generate-key") {
            this->config.operation = CryptoConfig::Operation::GENERATE_KEY;
        }
        else if (arg == "--encrypt") {
            this->config.operation = CryptoConfig::Operation::ENCRYPT;
        }
        else if (arg == "--decrypt") {
            this->config.operation = CryptoConfig::Operation::DECRYPT;
        }
        else if (arg == "--help") {
            print_help();
            this->config.is_valid = false;
            return this->config;
        }
        else {
            this->config.error_message = "Unknown argument: " + arg;
            this->config.is_valid = false;
            return this->config;
        }
    }

    // Validate the configuration
    this->config.validate();
    return this->config;
}

CryptoConfig ArgumentParser::get_config() const {
    return this->config;
}

void ArgumentParser::print_help() const{
    std::cout << this->argv[0] << ". AES Encryption Tool\n\n"
              << "Usage:\n"
              << "\tEncryption\t" << this->argv[0] << " --encrypt --key <keyfile> --input <file> --output <file> [options]\n"
              << "\tDecryption\t" << this->argv[0] << " --decrypt --key <keyfile> --input <file> --output <file> [options]\n"
              << "\tKey Generation:\t" << this->argv[0] << " --generate-key --key-length <bits> --output <file>\n\n"
              << "Options:\n"
              << "\t--mode <ECB|CBC>         Operation mode (default: CBC)\n"
              << "\t--key-length <bits>      Key length: 128, 192, or 256 (default: 128)\n"
              << "\t--help                   Show this help message\n";
}
