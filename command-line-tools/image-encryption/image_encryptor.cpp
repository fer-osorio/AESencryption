/**
 * @file image_encryptor.cpp
 * @brief AES image encryption tool supporting BMP, PNG, and JPEG formats.
 *
 * This program encrypts or decrypts image files using AES in ECB, CBC, OFB,
 * or CTR mode, dispatching to the correct File::FileBase subclass based on
 * the input file extension.
 *
 * Round-trip fidelity by format:
 *   BMP  — lossless container; encrypt → decrypt restores the original exactly.
 *   PNG  — lossless compression (DEFLATE); round-trip is exact.
 *   JPEG — lossy codec; decrypted output will NOT match the original.
 *          The program warns the user before proceeding.
 *
 * Usage:
 *   Encryption:     image_encryptor --key <file> --input <img> --output <img>
 *                       [--mode ECB|CBC|OFB|CTR] [--iv <32 hex chars>]
 *   Decryption:     image_encryptor --decrypt --key <file> --input <img>
 *                       --output <img> --iv <32 hex chars>
 *   Key generation: image_encryptor --generate-key --key-length <bits>
 *                       --output <file>
 */

#include "../../core-crypto/include/cipher.hpp"
#include "../../file-handlers/include/image_factory.hpp"
#include "../../cli-tools/include/cli_config.hpp"

#include <fstream>
#include <iostream>
#include <iomanip>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <vector>

using namespace CipherFortis;
using namespace CLIConfig;
using namespace File;

// ── Helpers ───────────────────────────────────────────────────────────────────

static std::vector<uint8_t> parse_hex_iv(const std::string& hex) {
    if (hex.size() != 32)
        throw std::invalid_argument("IV must be exactly 32 hex characters (16 bytes)");
    std::vector<uint8_t> iv(16);
    for (size_t i = 0; i < 16; ++i) {
        unsigned int byte;
        std::istringstream ss(hex.substr(i * 2, 2));
        if (!(ss >> std::hex >> byte))
            throw std::invalid_argument("Invalid hex in IV: " + hex);
        iv[i] = static_cast<uint8_t>(byte);
    }
    return iv;
}

static std::string bytes_to_hex(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i)
        oss << std::hex << std::uppercase << std::setfill('0') << std::setw(2)
            << static_cast<unsigned>(data[i]);
    return oss.str();
}

static bool mode_needs_iv(Cipher::OperationMode::Identifier m) {
    return m != Cipher::OperationMode::Identifier::ECB;
}

// ── ImageCryptoConfig ─────────────────────────────────────────────────────────

class ImageCryptoConfig : public CLIConfig::BaseCryptoConfig {
public:
    bool validate(const CLIConfig::ArgumentParser& parser) override;
    void print_help(const CLIConfig::ArgumentParser& parser) const;

    bool        decrypt      = false;
    bool        generate_key = false;
    std::string key_file, input_file, output_file, iv_hex, metadata_file;
    Key::LengthBits                   key_length     = Key::LengthBits::_128;
    Cipher::OperationMode::Identifier operation_mode = Cipher::OperationMode::Identifier::CBC;
};

bool ImageCryptoConfig::validate(const CLIConfig::ArgumentParser& parser) {
    if (parser.has("--help")) {
        print_help(parser);
        is_valid = false;
        return false;
    }

    generate_key  = parser.has("--generate-key");
    decrypt       = parser.has("--decrypt");
    iv_hex        = parser.getOr("--iv", "");
    metadata_file = parser.getOr("--metadata", "");

    // Key length
    std::string kl_str = parser.getOr("--key-length", "128");
    if      (kl_str == "128") key_length = Key::LengthBits::_128;
    else if (kl_str == "192") key_length = Key::LengthBits::_192;
    else if (kl_str == "256") key_length = Key::LengthBits::_256;
    else {
        error_message = "Invalid key length: " + kl_str + ". Use 128, 192, or 256.";
        is_valid = false;
        return false;
    }

    // Operation mode
    std::string mode_str = parser.getOr("--mode", "CBC");
    if      (mode_str == "ECB") operation_mode = Cipher::OperationMode::Identifier::ECB;
    else if (mode_str == "CBC") operation_mode = Cipher::OperationMode::Identifier::CBC;
    else if (mode_str == "OFB") operation_mode = Cipher::OperationMode::Identifier::OFB;
    else if (mode_str == "CTR") operation_mode = Cipher::OperationMode::Identifier::CTR;
    else {
        error_message = "Invalid mode: " + mode_str + ". Use ECB, CBC, OFB, or CTR.";
        is_valid = false;
        return false;
    }

    if (generate_key) {
        output_file = parser.getOr("--output", "");
        if (output_file.empty()) {
            error_message = "Missing required argument: --output";
            is_valid = false;
            return false;
        }
        is_valid = true;
        return true;
    }

    // Encrypt / decrypt path
    key_file    = parser.getOr("--key",    "");
    input_file  = parser.getOr("--input",  "");
    output_file = parser.getOr("--output", "");

    for (auto& [name, val] : std::vector<std::pair<std::string, std::string>>{
            {"--key", key_file}, {"--input", input_file}, {"--output", output_file}}) {
        if (val.empty()) {
            error_message = "Missing required argument: " + name;
            is_valid = false;
            return false;
        }
    }

    is_valid = true;
    return true;
}

void ImageCryptoConfig::print_help(const CLIConfig::ArgumentParser& parser) const {
    const char* prog = parser.program_name();
    std::cout
        << prog << " — AES Image Encryption Tool\n"
        << "Supported formats: BMP, PNG, JPEG (.jpg / .jpeg)\n\n"
        << "Usage:\n"
        << "  Encryption:     " << prog
            << " --key <keyfile> --input <img> --output <img> [options]\n"
        << "  Decryption:     " << prog
            << " --decrypt --key <keyfile> --input <img> --output <img>"
            << " --iv <hex> [options]\n"
        << "  Key generation: " << prog
            << " --generate-key --key-length <bits> --output <file>\n\n"
        << "Options:\n"
        << "  --decrypt                  Decrypt instead of encrypt (default: encrypt)\n"
        << "  --key-length <bits>        Key length in bits: 128, 192, or 256 (default: 128)\n"
        << "  --mode <ECB|CBC|OFB|CTR>   Operation mode (default: CBC)\n"
        << "  --iv <32 hex chars>        16-byte IV as 32 hex characters (CBC/OFB/CTR);\n"
        << "                             if omitted on encrypt, a random IV is generated\n"
        << "                             and printed to stdout\n"
        << "  --metadata <file>          JSON file to save IV+mode on encrypt,\n"
        << "                             or load IV+mode on decrypt (replaces --iv)\n"
        << "  --help                     Show this help message\n\n"
        << "Notes:\n"
        << "  BMP and PNG support lossless round-trips (encrypt then decrypt\n"
        << "  recovers the original). JPEG will be saved as PNG (lossless)\n"
        << "  to preserve encrypted pixels.\n";
}

// ── Metadata helpers ──────────────────────────────────────────────────────────

static void write_metadata(const std::string& path,
                            const std::string& mode, const std::string& iv_hex) {
    std::ofstream f(path);
    if (!f) throw std::runtime_error("Cannot open metadata file for writing: " + path);
    f << "{\n  \"mode\": \"" << mode << "\"";
    if (!iv_hex.empty())
        f << ",\n  \"iv\": \"" << iv_hex << "\"";
    f << "\n}\n";
}

static void read_metadata(const std::string& path,
                           std::string& mode, std::string& iv_hex) {
    std::ifstream f(path);
    if (!f) throw std::runtime_error("Cannot open metadata file: " + path);
    std::string content((std::istreambuf_iterator<char>(f)),
                         std::istreambuf_iterator<char>());
    auto extract = [&](const std::string& key) -> std::string {
        std::string search = "\"" + key + "\": \"";
        auto pos = content.find(search);
        if (pos == std::string::npos) return "";
        pos += search.size();
        auto end = content.find("\"", pos);
        return (end != std::string::npos) ? content.substr(pos, end - pos) : "";
    };
    mode   = extract("mode");
    iv_hex = extract("iv");
}

// ── main ──────────────────────────────────────────────────────────────────────

int main(int argc, const char* argv[]) {
    ArgumentParser parser(argc, argv);
    parser.parse();

    ImageCryptoConfig config;

    if (argc < 2) {
        config.print_help(parser);
        return 1;
    }

    config.validate(parser);
    if (!config.is_valid) {
        std::cerr << "Error: " << config.error_message << "\n";
        return 1;
    }

    try {
        // ── Key generation ────────────────────────────────────────────────────
        if (config.generate_key) {
            Key key(config.key_length);
            key.save(config.output_file.c_str());
            std::cout << "Key saved to: " << config.output_file << "\n";
            return 0;
        }

        // ── Encrypt / Decrypt ─────────────────────────────────────────────────

        // Load metadata before optmode creation so mode/IV override takes effect
        if (config.decrypt && !config.metadata_file.empty()) {
            std::string mode_str, iv_from_meta;
            read_metadata(config.metadata_file, mode_str, iv_from_meta);
            if (!mode_str.empty())
                config.operation_mode = Cipher::OperationMode::string_to_identifier(mode_str);
            if (config.iv_hex.empty())
                config.iv_hex = iv_from_meta;
        }

        Key key(config.key_file.c_str());
        Cipher::OperationMode optmode(config.operation_mode);

        if (!config.iv_hex.empty()) {
            optmode.setInitialVector(parse_hex_iv(config.iv_hex));
        } else if (mode_needs_iv(config.operation_mode)) {
            // Auto-generated IV: print it so the user can reuse it for decryption
            const uint8_t* iv_ptr = optmode.getIVpointerData();
            std::cout << "Generated IV (save for decryption): "
                      << bytes_to_hex(iv_ptr, 16) << "\n";
        }

        if (!config.decrypt && image_is_lossy(config.input_file)) {
            config.output_file = std::filesystem::path(config.output_file)
                                     .replace_extension(".png").string();
            std::cout << "Note: JPEG input will be saved as PNG to preserve encrypted pixels.\n"
                      << "      Output: " << config.output_file << "\n";
        }

        std::unique_ptr<FileBase> image = make_image(config.input_file);
        Cipher cipher(key, optmode);
        image->load();

        if (config.decrypt) {
            image->apply_decryption(cipher);
            std::cout << "Decrypted: " << config.input_file
                      << " -> "        << config.output_file << "\n";
        } else {
            image->apply_encryption(cipher);
            std::cout << "Encrypted: " << config.input_file
                      << " -> "        << config.output_file << "\n";
        }

        image->save(config.output_file);

        if (!config.decrypt && !config.metadata_file.empty()) {
            std::string iv_hex_out;
            if (mode_needs_iv(config.operation_mode))
                iv_hex_out = bytes_to_hex(optmode.getIVpointerData(), 16);
            write_metadata(config.metadata_file,
                           Cipher::OperationMode::identifier_to_string(config.operation_mode),
                           iv_hex_out);
        }

    } catch (const std::invalid_argument& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
