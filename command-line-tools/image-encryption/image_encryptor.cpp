/**
 * @file image_encryptor.cpp
 * @brief AES image encryption tool supporting BMP, PNG, and JPEG formats.
 *
 * This program is a generalisation of bmp_encryptor. It encrypts or decrypts
 * image files using AES in ECB, CBC, OFB, or CTR mode, dispatching to the
 * correct File::FileBase subclass based on the input file extension.
 *
 * Round-trip fidelity by format:
 *   BMP  — lossless container; encrypt → decrypt restores the original exactly.
 *   PNG  — lossless compression (DEFLATE); round-trip is exact.
 *   JPEG — lossy codec; decrypted output will NOT match the original.
 *          The program warns the user before proceeding.
 *
 * Usage:
 *   Encryption:     image_encryptor --encrypt --key <file> --input <img>
 *                       --output <img> [--mode ECB|CBC|OFB|CTR]
 *   Decryption:     image_encryptor --decrypt --key <file> --input <img>
 *                       --output <img> --mode-data <file>
 *   Key generation: image_encryptor --generate-key --key-length <bits>
 *                       --output <file>
 */

#include "../../core-crypto/include/cipher.hpp"
#include "../../file-handlers/include/image_factory.hpp"
#include "../../cli-tools/include/cli_config.hpp"

#include <iostream>
#include <memory>
#include <stdexcept>

using namespace CipherFortis;
using namespace CLIConfig;
using namespace File;

// ── ImageCryptoConfig ─────────────────────────────────────────────────────────

/**
 * @class ImageCryptoConfig
 * @brief Thin FileCryptoConfig subclass for the multi-format image encryptor.
 *
 * The only additions over the base class are:
 *   - A customised help text that names the supported formats.
 *   - A JPEG lossy-codec warning emitted during validate().
 *
 * All validation logic and factory methods (create_key, create_optmode)
 * are inherited unchanged from FileCryptoConfig.
 */
class ImageCryptoConfig : public CLIConfig::FileCryptoConfig {
public:
    bool validate(const CLIConfig::ArgumentParser& parser) override {
        if (!FileCryptoConfig::validate(parser)) return false;

        // Warn the user when the input is a JPEG and the operation is
        // encrypt or decrypt — the lossy codec will corrupt the encrypted
        // bytes on re-encode, so decryption cannot recover the original.
        if (operation != Operation::GENERATE_KEY && image_is_lossy(input_file)) {
            std::cerr
                << "Warning: '" << input_file.filename().string() << "' is a JPEG.\n"
                << "  JPEG uses lossy compression. Encrypted bytes will be altered\n"
                << "  by the codec on save, so decryption will NOT restore the\n"
                << "  original image. The visual encryption effect is still visible.\n"
                << "  Use BMP or PNG for a lossless round-trip.\n\n";
        }

        return true;
    }

    void print_help(const CLIConfig::ArgumentParser& parser) const override {
        const char* prog = parser.program_name();
        std::cout
            << prog << " — AES Image Encryption Tool\n"
            << "Supported formats: BMP, PNG, JPEG (.jpg / .jpeg)\n\n"
            << "Usage:\n"
            << "  Encryption:     " << prog
                << " --encrypt --key <keyfile> --input <img> --output <img> [options]\n"
            << "  Decryption:     " << prog
                << " --decrypt --key <keyfile> --input <img> --output <img>"
                << " --mode-data <file> [options]\n"
            << "  Key generation: " << prog
                << " --generate-key --key-length <bits> --output <file>\n\n"
            << "Options:\n"
            << "  --key-length <bits>        Key length in bits: 128, 192, or 256 (default: 128)\n"
            << "  --mode <ECB|CBC|OFB|CTR>   Operation mode (default: CBC)\n"
            << "  --mode-data <file>         Saved operation-mode data (IV/counter);\n"
            << "                             required for decryption in CBC, OFB, CTR\n"
            << "  --help                     Show this help message\n\n"
            << "Notes:\n"
            << "  BMP and PNG support lossless round-trips (encrypt then decrypt\n"
            << "  recovers the original). JPEG is lossy: decryption will not\n"
            << "  restore the original image.\n";
    }
};

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
        if (config.operation == ImageCryptoConfig::Operation::GENERATE_KEY) {
            Key key(config.key_length);
            key.save(config.output_file.c_str());
            std::cout << "Key saved to: " << config.output_file << "\n";
            return 0;
        }

        // ── Encrypt / Decrypt ─────────────────────────────────────────────────
        std::unique_ptr<FileBase> image = make_image(config.input_file);
        Cipher::OperationMode optmode  = config.create_optmode();
        Cipher cipher(config.create_key(), optmode);

        image->load();

        if (config.operation == ImageCryptoConfig::Operation::ENCRYPT) {
            image->apply_encryption(cipher);
            std::cout << "Encrypted: " << config.input_file
                      << " -> "        << config.output_file << "\n";
        } else {
            image->apply_decryption(cipher);
            std::cout << "Decrypted: " << config.input_file
                      << " -> "        << config.output_file << "\n";
        }

        image->save(config.output_file);

        // Save operation-mode data (IV / counter) when not loaded from file,
        // so the user has everything needed for a later decryption call.
        if (config.mode_file.empty()) {
            optmode.save(config.output_file.string() + ".optmode");
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
