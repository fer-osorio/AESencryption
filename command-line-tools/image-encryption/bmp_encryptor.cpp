#include "../../include/cipher.hpp"
#include "../../file-handlers/include/bitmap.hpp"
#include "../../CLI/include/cli_config.hpp"

int main(int argc, const char* argv[]){
    // Parsing arguments. Converting user intput to valid arguments for this program.
    const CLI::CryptoConfig cryp_conf= CLI::ArgumentParser(argc,argv).parse();
    if(!cryp_conf.is_valid){
        std::cerr << cryp_conf.error_message;
        return 1;
    }

    try{
        if(cryp_conf.operation == CLI::CryptoConfig::Operation::ENCRYPT
            || cryp_conf.operation == CLI::CryptoConfig::Operation::DECRYPT){
            // Resource acquisition
            File::Bitmap bmp(cryp_conf.input_file);
            AESencryption::Cipher ciph(cryp_conf.create_key(), cryp_conf.operation_mode);
            bmp.load();
            // Data processing: Encryption
            if(cryp_conf.operation == CLI::CryptoConfig::Operation::ENCRYPT) bmp.apply_encryption(ciph);
            if(cryp_conf.operation == CLI::CryptoConfig::Operation::DECRYPT) bmp.apply_decryption(ciph);
            bmp.save(cryp_conf.output_file);
            // Return with success status
            return 0;
        }
        if(cryp_conf.operation == CLI::CryptoConfig::Operation::GENERATE_KEY){
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
