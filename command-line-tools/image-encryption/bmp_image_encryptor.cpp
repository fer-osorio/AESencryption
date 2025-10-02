#include "../include/cipher.hpp"
#include "../file-handlers/include/bitmap.hpp"
#include "../CLI/include/cli_config.hpp"
#include <memory>

int main(int argc, const char* argv[]){
    // Parsing arguments. Converting user intput to valid arguments for this program.
    const CLI::CryptoConfig cryp_conf= CLI::ArgumentParser(argc,argv).parse();
    if(!cryp_conf.is_valid){
        std::cerr << cryp_conf.error_message;
        return 1;
    }

    std::unique_ptr<AESencryption::Cipher> ciph = nullptr;
    std::unique_ptr<File::Bitmap> bmp = nullptr;
    try{
        // Resource acquisition
        bmp = std::make_unique<File::Bitmap>(
            File::Bitmap(cryp_conf.input_file)
        );
        ciph = std::make_unique<AESencryption::Cipher>(
            AESencryption::Cipher(cryp_conf.create_key(), cryp_conf.operation_mode)
        );

        // Data processing: Encryption
        bmp->apply_encryption(*ciph);
        bmp->save(cryp_conf.output_file);
    }catch(const std::exception& exp){
        std::cerr << exp.what();
        return 1;
    }


    return 0;
}
