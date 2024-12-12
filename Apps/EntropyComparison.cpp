#include"../Source/File.hpp"

int main(int argc, char* argv[]) {
    if(argc == 2) {
        AES::Key k;
        AES::Key::Length klen;
        AES::Cipher AEScph = AES::Cipher(k);
        File::Bitmap bmp;
        double entropy[4][3];
        try {
            bmp = File::Bitmap(argv[1]);
        } catch(std::runtime_error& exp) {;
            std::cerr << "Could not create File::Bitmap object.\n" << exp.what();
            return EXIT_FAILURE;
        }
        const File::Bitmap bmp__ = bmp;
        std::cout << '\n' << argv[1] << " characteristics:\n\n";
        std::cout << bmp << "\n\n";

        for(int i = 0; i < 3; i++){
            if(i == 0) klen = AES::Key::_128;
            if(i == 1) klen = AES::Key::_192;
            if(i == 2) klen = AES::Key::_256;

            k = AES::Key(klen, AES::Key::ECB);
            AEScph = AES::Cipher(k);
            //std::cout << AEScph << '\n';
            encrypt(bmp, AEScph, false, false);
            entropy[0][0] = bmp.computeEntropyRed();
            entropy[1][0] = bmp.computeEntropyGreen();
            entropy[2][0] = bmp.computeEntropyBlue();
            entropy[3][0] = bmp.computeEntropy();
            decrypt(bmp, AEScph, false);

            if(bmp__ != bmp) std::cout << "Something went wrong with decryption" << std::endl;

            k = AES::Key(klen, AES::Key::CBC);
            AEScph = AES::Cipher(k);
            //std::cout << AEScph << '\n';
            encrypt(bmp, AEScph, false, false);
            entropy[0][1] = bmp.computeEntropyRed();
            entropy[1][1] = bmp.computeEntropyGreen();
            entropy[2][1] = bmp.computeEntropyBlue();
            entropy[3][1] = bmp.computeEntropy();
            decrypt(bmp, AEScph, false);

            if(bmp__ != bmp) std::cout << "Something went wrong with decryption" << std::endl;

            k = AES::Key(klen, AES::Key::PVS);
            AEScph = AES::Cipher(k);
            //std::cout << AEScph << '\n';
            encrypt(bmp, AEScph, false, false);
            entropy[0][2] = bmp.computeEntropyRed();
            entropy[1][2] = bmp.computeEntropyGreen();
            entropy[2][2] = bmp.computeEntropyBlue();
            entropy[3][2] = bmp.computeEntropy();
            decrypt(bmp, AEScph, false);

            if(bmp__ != bmp) std::cout << "Something went wrong with decryption" << std::endl;

            std::cout << std::fixed << std::endl;
            std::cout << "Entropy. Key size = " << (int)klen << " -------------------\n";
            std::cout << "                ECV      CBC      PVS     \n";
            std::cout << "Entropy red     " << std::setprecision(6) << entropy[0][0] << ' ' << entropy[0][1] << ' ' << entropy[0][2] << '\n';
            std::cout << "Entropy green   " << std::setprecision(6) << entropy[1][0] << ' ' << entropy[1][1] << ' ' << entropy[1][2] << '\n';
            std::cout << "Entropy blue    " << std::setprecision(6) << entropy[2][0] << ' ' << entropy[2][1] << ' ' << entropy[2][2] << '\n';
            std::cout << "Overall entropy " << std::setprecision(6) << entropy[3][0] << ' ' << entropy[3][1] << ' ' << entropy[3][2] << '\n';
            std::cout << std::endl;
        }
    }
    return 0;
}
