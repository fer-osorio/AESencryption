#include<iostream>
#include"../Source/File.hpp"
#include<plstream.h>

int main(int argc, const char* argv[]){
    if(argc == 3){
        AES::Key k;
        try{
            k = AES::Key(argv[1]);
        } catch(const std::runtime_error& exp){
            std::cout << "Could not open aeskey file..." << exp.what() << "\n";
            return 0;
        }
        AES::Cipher ch(k);
        File::Bitmap bmp;
        try{
            bmp = File::Bitmap(argv[2]);
        } catch(const std::runtime_error& exp){
            std::cout << "Could not open bitmap file..." << exp.what() << "\n";
            return 0;
        }
        File::BitmapStatistics BS(&bmp);
        uint8_t* X = new uint8_t[bmp.PixelAmount()];
        uint8_t* Y = new uint8_t[bmp.PixelAmount()];

        plstream p;
        p.sdev("pngcairo");
        p.sfnam("Original.png");
        p.init();
        p.env(0, 255, 0, 255, 0, 0);                                            // Set up the plotting area
        p.lab("X Value", "Y Value", "Original Plot");
        p.col0(4);                                                              // Set point color and size to Blue

        BS.retreaveCorrelation(File::Bitmap::ColorID::Green, File::Bitmap::diagonal, X, Y);
        p.poin(bmp.PixelAmount(), X, Y, 4);                                     // Draw the scatter points with symbol code 4 (filled circle)

        encrypt(bmp,ch,false);
        BS = File::BitmapStatistics(&bmp);
        BS.retreaveCorrelation(File::Bitmap::ColorID::Green, File::Bitmap::diagonal, X, Y);
        p.sfnam("Encrypted.png");
        p.lab("X Value", "Y Value", "Encrypted Plot");
        p.poin(bmp.PixelAmount(), X, Y, 4);                                     // Draw the scatter points with symbol code 4 (filled circle)

        p.end();
        if(X != NULL) delete[] X;
        if(Y != NULL) delete[] Y;
    }
    return 0;
}
