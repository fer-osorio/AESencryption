#include"../Source/File.hpp"
#define KEY_SIZE_AMOUNT  3
#define OPERATION_MODE_AMOUNT 3

int main(int argc, char* argv[]) {
    if(argc == 2) {
        AES::Key key;
        AES::Key::Length klen;
        AES::Key::OperationMode opm;
        AES::Cipher AEScph = AES::Cipher(key);
        File::Bitmap bmp;
        File::BitmapStats bmpSts;
        double entropy[PIXEL_COMPONENTS_AMOUNT][OPERATION_MODE_AMOUNT];
        double XiSquare[PIXEL_COMPONENTS_AMOUNT][OPERATION_MODE_AMOUNT];
        double correlation[PIXEL_COMPONENTS_AMOUNT][DIRECTIONS_AMOUNT][OPERATION_MODE_AMOUNT];
        int i, j, k, l;

        try {
            bmp = File::Bitmap(argv[1]);
        } catch(std::runtime_error& exp) {;
            std::cerr << "Could not create File::Bitmap object.\n" << exp.what();
            return EXIT_FAILURE;
        }

        const File::Bitmap bmp__ = bmp;
        std::cout << '\n' << argv[1] << " characteristics:\n\n";
        std::cout << bmp << "\n\n";

        for(i = 0; i < KEY_SIZE_AMOUNT; i++){
            switch(i){
                case 0: klen = AES::Key::_128;
                    break;
                case 1: klen = AES::Key::_192;
                    break;
                case 2: klen = AES::Key::_256;
                    break;
                default:klen = AES::Key::_256;
            }

            for(j = 0; j < OPERATION_MODE_AMOUNT; j++){
                switch(j){
                    case 0: opm = AES::Key::ECB;
                        break;
                    case 1: opm = AES::Key::CBC;
                        break;
                    case 2: opm = AES::Key::PVS;
                        break;
                    default:opm = AES::Key::ECB;
                }
                key = AES::Key(klen, opm);
                AEScph = AES::Cipher(key);
                //std::cout << AEScph << '\n';
                encrypt(bmp, AEScph, false);
                bmpSts = File::BitmapStats(&bmp);
                for(k = 0; k < PIXEL_COMPONENTS_AMOUNT; k++) {
                    entropy[k][j] = bmpSts.retreaveEntropy(File::Bitmap::ColorID(k));
                    XiSquare[k][j] = bmpSts.retreaveXiSquare(File::Bitmap::ColorID(k));
                    for(l = 0; l < DIRECTIONS_AMOUNT; l++){
                        correlation[k][l][j] = bmpSts.retreaveCorrelation(File::Bitmap::ColorID(k), File::Bitmap::Direction(l));
                    }
                }
                decrypt(bmp, AEScph, false);
                if(bmp__ != bmp) std::cout << "Something went wrong with decryption" << std::endl;
            }

            std::cout << std::fixed << std::setprecision(5) <<std::endl;
            std::cout << "Key size = " << (int)klen << " -----------------------------------\n\n";
            std::cout << "Entropy        ECV      CBC      PVS     \n";
            std::cout << "Red          " << entropy[0][0] << ' ' << entropy[0][1] << ' ' << entropy[0][2] << '\n';
            std::cout << "Green        " << entropy[1][0] << ' ' << entropy[1][1] << ' ' << entropy[1][2] << '\n';
            std::cout << "Blue         " << entropy[2][0] << ' ' << entropy[2][1] << ' ' << entropy[2][2] << '\n';

            std::cout << std::endl;

            std::cout << "XiSquare        ECV      CBC      PVS     \n";
            std::cout << "Red          " << XiSquare[0][0] << ' ' << XiSquare[0][1] << ' ' << XiSquare[0][2] << '\n';
            std::cout << "Green        " << XiSquare[1][0] << ' ' << XiSquare[1][1] << ' ' << XiSquare[1][2] << '\n';
            std::cout << "Blue         " << XiSquare[2][0] << ' ' << XiSquare[2][1] << ' ' << XiSquare[2][2] << '\n';

            std::cout << std::endl;

            for(k = 0; k < DIRECTIONS_AMOUNT; k++){
                if(k == File::Bitmap::horizontal) std::cout << "Horizontal Correlation    ECV      CBC      PVS     \n";
                if(k == File::Bitmap::vertical)   std::cout << "Vertical Correlation      ECV      CBC      PVS     \n";
                std::cout << "Red                    ";
                for(l = 0; l < OPERATION_MODE_AMOUNT; l++) std::cout << (correlation[0][k][l] < 0 ? "" : " ") << correlation[0][k][l] << ' ';
                std::cout << '\n' << "Green                  ";
                for(l = 0; l < OPERATION_MODE_AMOUNT; l++) std::cout << (correlation[1][k][l] < 0 ? "" : " ") << correlation[1][k][l] << ' ';
                std::cout << '\n' << "Blue                   ";
                for(l = 0; l < OPERATION_MODE_AMOUNT; l++) std::cout << (correlation[2][k][l] < 0 ? "" : " ") << correlation[2][k][l] << ' ';
                std::cout << '\n';
                std::cout << std::endl;
            }
            std::cout << std::endl;
        }
    }
    return 0;
}
