#include "../../include/cipher.hpp"
#include "../../file-handlers/include/bitmap.hpp"
#include "../../metrics-analysis/include/data_randomness.hpp"
#include "../../crypto-cli/include/cli_config.hpp"
#include <memory>

void output_metrics_results(const DataRandomness& input_metrics, const DataRandomness& output_metrics);

int main(int argc, const char* argv[]){
    // Parsing arguments. Converting user intput to valid arguments for this program.
    const CLIConfig::CryptoConfig cryp_conf= CLIConfig::ArgumentParser(argc,argv).parse();
    if(!cryp_conf.is_valid){
        std::cerr << cryp_conf.error_message;
        return 1;
    }

    try{
        if(cryp_conf.operation == CLIConfig::CryptoConfig::Operation::ENCRYPT
            || cryp_conf.operation == CLIConfig::CryptoConfig::Operation::DECRYPT){
            File::Bitmap bmp(cryp_conf.input_file);
            AESencryption::Cipher ciph(cryp_conf.create_key(), cryp_conf.operation_mode);
            std::unique_ptr<DataRandomness> input_rand = nullptr;
            std::unique_ptr<DataRandomness> output_rand = nullptr;
            bmp.load();
            // Data processing
            if(cryp_conf.show_metrics){
                input_rand = std::make_unique<DataRandomness>(bmp.calculate_randomness());
            }
            if(cryp_conf.operation == CLIConfig::CryptoConfig::Operation::ENCRYPT) bmp.apply_encryption(ciph);
            if(cryp_conf.operation == CLIConfig::CryptoConfig::Operation::DECRYPT) bmp.apply_decryption(ciph);
            if(cryp_conf.show_metrics){
                output_rand = std::make_unique<DataRandomness>(bmp.calculate_randomness());
                output_metrics_results(*input_rand, *output_rand);
            }
            bmp.save(cryp_conf.output_file);
            // Return with success status
            return 0;
        }
        if(cryp_conf.operation == CLIConfig::CryptoConfig::Operation::GENERATE_KEY){
            AESencryption::Key key(cryp_conf.key_length);
            key.save(cryp_conf.output_file.c_str());
            return 0;
        }
    }catch(const std::exception& exp){
        std::cerr << exp.what();
        return 1;   // Return with failure status
    }

    return 0;
}

void output_metrics_results(const DataRandomness& input_metrics, const DataRandomness& output_metrics){
    std::cout << "{\n";
    std::cout << "  \"data_analysis\": [\n";
    std::cout << "      \"input_metrics\": {\n";
    std::cout << "          \"entropy\": " << input_metrics.getEntropy() << ",\n";
    std::cout << "          \"correlation\": " << input_metrics.getCorrelationAdjacentByte() << ",\n";
    std::cout << "          \"xi_square\": " << input_metrics.getChiSquare() << "\n";
    std::cout << "      },\n";
    std::cout << "      \"output_metrics\": {\n";
    std::cout << "          \"entropy\": " << output_metrics.getEntropy() << ",\n";
    std::cout << "          \"correlation\": " << output_metrics.getCorrelationAdjacentByte() << ",\n";
    std::cout << "          \"xi_square\": " << output_metrics.getChiSquare() << "\n";
    std::cout << "      }\n";
    std::cout << "  ]";
    std::cout << "\n";
    std::cout << "}\n";
}
