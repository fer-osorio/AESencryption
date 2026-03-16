#include "../../hsm/include/hsm_session.hpp"
#include "../../hsm/include/hsm_cipher.hpp"
#include "../../hsm/include/hsm_key_handle.hpp"
#include "../../include/cipher.hpp"
#include "../../include/key.hpp"
#include "../../file-handlers/include/file_base.hpp"

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

static void print_usage(const char* prog) {
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
    if (argc < 2) { print_usage(argv[0]); return 1; }

    std::string lib_path, token_label, pin, mode_str, keybits_str,
                key_label, input_path, output_path, iv_hex;
    bool decrypt = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        auto next = [&]() -> std::string {
            if (i + 1 >= argc)
                throw std::invalid_argument("Missing value for " + arg);
            return argv[++i];
        };
        if      (arg == "--lib")     lib_path     = next();
        else if (arg == "--token")   token_label  = next();
        else if (arg == "--pin")     pin          = next();
        else if (arg == "--mode")    mode_str     = next();
        else if (arg == "--keybits") keybits_str  = next();
        else if (arg == "--key")     key_label    = next();
        else if (arg == "--input")   input_path   = next();
        else if (arg == "--output")  output_path  = next();
        else if (arg == "--iv")      iv_hex       = next();
        else if (arg == "--decrypt") decrypt      = true;
        else { std::cerr << "Unknown argument: " << arg << "\n"; return 1; }
    }

    // Validate required arguments.
    for (auto& [name, val] : std::vector<std::pair<std::string,std::string>>{
            {"--lib",    lib_path},    {"--token",   token_label},
            {"--pin",    pin},         {"--mode",    mode_str},
            {"--keybits",keybits_str}, {"--key",     key_label},
            {"--input",  input_path},  {"--output",  output_path}}) {
        if (val.empty()) {
            std::cerr << "Missing required argument: " << name << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    try {
        auto mode     = parse_mode(mode_str);
        auto keybits  = parse_keybits(keybits_str);

        // ── Session & cipher setup ────────────────────────────────────────────
        HSMSession session(lib_path, token_label, pin);
        HSMCipher  cipher(session, mode);

        // ── Key: reuse existing or generate new ───────────────────────────────
        HSMKeyHandle key;
        try {
            key = cipher.findKey(key_label);
            std::cout << "Using existing HSM key: " << key_label << "\n";
        } catch (const std::runtime_error&) {
            key = cipher.generateKey(keybits, key_label);
            std::cout << "Generated new HSM key:  " << key_label << "\n";
        }
        cipher.setActiveKey(key);

        // ── IV handling ───────────────────────────────────────────────────────
        if (mode_needs_iv(mode)) {
            std::vector<uint8_t> iv;
            if (!iv_hex.empty()) {
                iv = parse_hex_iv(iv_hex);
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
        File::FileBase file(input_path);
        file.load();

        if (decrypt) {
            file.apply_decryption(cipher);
            std::cout << "Decrypted: " << input_path
                      << " -> " << output_path << "\n";
        } else {
            file.apply_encryption(cipher);
            std::cout << "Encrypted: " << input_path
                      << " -> " << output_path << "\n";
        }

        file.save(output_path);

    } catch (const PKCS11Exception& e) {
        std::cerr << "[PKCS#11 error] " << e.what() << "\n";
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "[error] " << e.what() << "\n";
        return 1;
    }

    return 0;
}
