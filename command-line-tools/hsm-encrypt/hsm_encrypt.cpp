#include "../../hsm/include/hsm_session.hpp"
#include "../../hsm/include/hsm_cipher.hpp"
#include "../../hsm/include/hsm_key_handle.hpp"
#include "../../include/cipher.hpp"
#include "../../include/key.hpp"
#include "../../file-handlers/include/file_base.hpp"
#include "../../crypto-cli/include/cli_config.hpp"

#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>
#include <iomanip>
#include <sstream>
#include <cstring>

using namespace AESencryption;
using namespace AESencryption::HSM;

// ── Helpers ───────────────────────────────────────────────────────────────────

static Cipher::OperationMode::Identifier parse_mode(const std::string& s) {
    if (s == "ecb") return Cipher::OperationMode::Identifier::ECB;
    if (s == "cbc") return Cipher::OperationMode::Identifier::CBC;
    if (s == "ctr") return Cipher::OperationMode::Identifier::CTR;
    throw std::invalid_argument("Unknown mode: " + s);
}

static Key::LengthBits parse_keybits(const std::string& s) {
    if (s == "128") return Key::LengthBits::_128;
    if (s == "192") return Key::LengthBits::_192;
    if (s == "256") return Key::LengthBits::_256;
    throw std::invalid_argument("Invalid keybits (must be 128, 192, or 256): " + s);
}

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

// ── HSMCryptoConfig ───────────────────────────────────────────────────────────

class HSMCryptoConfig : public CLIConfig::BaseCryptoConfig {
public:
    bool validate(const CLIConfig::ArgumentParser& parser) override;
    void print_help(const CLIConfig::ArgumentParser& parser) const;

    std::string lib_path, token, pin, key_label, input_file, output_file;
    std::string iv_hex;
    bool        decrypt        = false;
    Cipher::OperationMode::Identifier operation_mode = Cipher::OperationMode::Identifier::CBC;
    Key::LengthBits                   key_length     = Key::LengthBits::_128;
};

bool HSMCryptoConfig::validate(const CLIConfig::ArgumentParser& parser) {
    lib_path    = parser.getOr("--lib",     "");
    token       = parser.getOr("--token",   "");
    pin         = parser.getOr("--pin",     "");
    key_label   = parser.getOr("--key",     "");
    input_file  = parser.getOr("--input",   "");
    output_file = parser.getOr("--output",  "");
    iv_hex      = parser.getOr("--iv",      "");
    decrypt     = parser.has("--decrypt");

    // Check required fields
    for (auto& [name, val] : std::vector<std::pair<std::string, std::string>>{
            {"--lib",     lib_path},  {"--token",   token},
            {"--pin",     pin},       {"--key",     key_label},
            {"--input",   input_file},{"--output",  output_file}}) {
        if (val.empty()) {
            error_message = "Missing required argument: " + name;
            is_valid = false;
            return false;
        }
    }

    std::string mode_str    = parser.getOr("--mode",    "");
    std::string keybits_str = parser.getOr("--keybits", "");

    if (mode_str.empty()) {
        error_message = "Missing required argument: --mode";
        is_valid = false;
        return false;
    }
    if (keybits_str.empty()) {
        error_message = "Missing required argument: --keybits";
        is_valid = false;
        return false;
    }

    try {
        operation_mode = parse_mode(mode_str);
        key_length     = parse_keybits(keybits_str);
    } catch (const std::exception& e) {
        error_message = e.what();
        is_valid = false;
        return false;
    }

    is_valid = true;
    return true;
}

void HSMCryptoConfig::print_help(const CLIConfig::ArgumentParser& parser) const {
    const char* prog = parser.program_name();
    std::cerr
        << "Usage: " << prog << " [options]\n"
        << "\nRequired:\n"
        << "  --lib    PATH    PKCS#11 library path\n"
        << "                   e.g. /usr/lib64/pkcs11/libsofthsm2.so\n"
        << "  --token  LABEL   Token label\n"
        << "  --pin    PIN     User PIN\n"
        << "  --mode   MODE    Operation mode: ecb | cbc | ctr\n"
        << "  --keybits N      Key length in bits: 128 | 192 | 256\n"
        << "  --key    LABEL   Key label in the HSM\n"
        << "  --input  FILE    Input file path\n"
        << "  --output FILE    Output file path\n"
        << "\nOptional:\n"
        << "  --decrypt        Decrypt instead of encrypt (default: encrypt)\n"
        << "  --iv     HEX     16-byte IV as 32 hex characters (CBC/CTR)\n"
        << "                   If omitted, a random IV is generated and printed\n";
}

static std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
    std::ostringstream oss;
    for (auto b : bytes)
        oss << std::hex << std::uppercase << std::setfill('0') << std::setw(2)
            << static_cast<unsigned>(b);
    return oss.str();
}

static bool mode_needs_iv(Cipher::OperationMode::Identifier m) {
    return m != Cipher::OperationMode::Identifier::ECB;
}

// ── main ──────────────────────────────────────────────────────────────────────

int main(int argc, const char* argv[]) {
    CLIConfig::ArgumentParser parser(argc, argv);
    parser.parse();
    HSMCryptoConfig config;
    config.validate(parser);
    if (!config.is_valid) {
        std::cerr << config.error_message << "\n";
        config.print_help(parser);
        return 1;
    }

    try {
        // ── Session & cipher setup ────────────────────────────────────────────
        HSMSession session(config.lib_path, config.token, config.pin);
        HSMCipher  cipher(session, config.operation_mode);

        // ── Key: reuse existing or generate new ───────────────────────────────
        HSMKeyHandle key;
        try {
            key = cipher.findKey(config.key_label);
            std::cout << "Using existing HSM key: " << config.key_label << "\n";
        } catch (const std::runtime_error&) {
            key = cipher.generateKey(config.key_length, config.key_label);
            std::cout << "Generated new HSM key:  " << config.key_label << "\n";
        }
        cipher.setActiveKey(key);

        // ── IV handling ───────────────────────────────────────────────────────
        if (mode_needs_iv(config.operation_mode)) {
            std::vector<uint8_t> iv;
            if (!config.iv_hex.empty()) {
                iv = parse_hex_iv(config.iv_hex);
            } else {
                // Generate a random IV via the HSM's RNG.
                iv.resize(16);
                CK_RV rv = session.p11()->C_GenerateRandom(
                    session.session(), iv.data(), 16
                );
                if (rv != CKR_OK)
                    throw PKCS11Exception("C_GenerateRandom (IV)", rv);
                std::cout << "Generated IV (save for decryption): "
                          << bytes_to_hex(iv) << "\n";
            }
            cipher.setIV(iv);
        }

        // ── File I/O via FileBase ─────────────────────────────────────────────
        File::FileBase file(config.input_file);
        file.load();

        if (config.decrypt) {
            file.apply_decryption(cipher);
            std::cout << "Decrypted: " << config.input_file
                      << " -> " << config.output_file << "\n";
        } else {
            file.apply_encryption(cipher);
            std::cout << "Encrypted: " << config.input_file
                      << " -> " << config.output_file << "\n";
        }

        file.save(config.output_file);

    } catch (const PKCS11Exception& e) {
        std::cerr << "[PKCS#11 error] " << e.what() << "\n";
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "[error] " << e.what() << "\n";
        return 1;
    }

    return 0;
}
