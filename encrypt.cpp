#include<iostream>
#include"Source/Bitmap.hpp"

int main(int argc, char *argv[]) {
    char key256[] = {(char)0x60, (char)0x3D, (char)0xEB, (char)0x10,
                     (char)0x15, (char)0xCA, (char)0x71, (char)0xBE,
                     (char)0x2B, (char)0x73, (char)0xAE, (char)0xF0,
                     (char)0x85, (char)0x7D, (char)0x77, (char)0x81,
                     (char)0x1F, (char)0x35, (char)0x2C, (char)0x07,
                     (char)0x3B, (char)0x61, (char)0x08, (char)0xD7,
                     (char)0x2D, (char)0x98, (char)0x10, (char)0xA3,
                     (char)0x09, (char)0x14, (char)0xDF, (char)0xF4};

    char key192[] = {(char)0x8E, (char)0x73, (char)0xB0, (char)0xF7,
                     (char)0xDA, (char)0x0E, (char)0x64, (char)0x52,
                     (char)0xC8, (char)0x10, (char)0xF3, (char)0x2B,
                     (char)0x80, (char)0x90, (char)0x79, (char)0xE5,
                     (char)0x62, (char)0xF8, (char)0xEA, (char)0xD2,
                     (char)0x52, (char)0x2C, (char)0x6B, (char)0x7B};

    char key128[]= {char(0x2B), char(0x7E), char(0x15), char(0x16),
                    char(0x28), char(0xAE), char(0xD2), char(0xA6),
                    char(0xAB), char(0xF7), char(0x15), char(0x88),
                    char(0x09), char(0xCF), char(0x4F), char(0x3C)};
    char IV[16];
    if(argc > 1) {
        Bitmap img(argv[1]);
        AES e(key256, AESkey::_256);
        encryptCBC(img, e, IV);
        for(int i = 2; i < argc; i++) {
            img = Bitmap(argv[i]);
            encryptCBC(img, e, IV);
        }
        return 0;
    }

    char input[1025]; // Maximum size 1024 characters without EOF.
    char copy[1025];
    unsigned size = 0, i;
    std::cout << "\nWrite the string you want to encrypt. To process the "
                 "string sent the value 'EOF', which you can do by:\n\n"
                 "- Pressing twice the keys CTRL-Z for Windows.\n"
                 "- Pressing twice the keys CTRL-D for Unix and Linux.\n\n";
    while((input[size++] = getchar()) != EOF) { // Input from terminal.
        if(size > 1024) {
            std::cout << "\n\nMaximum size (1024 characters) reached. "
                         "Processing the first 1024 characters.\n\n";
            break;
        }
    }
    input[--size] = 0; // End of string.
    AES e(key256, AESkey::_256);
    // -Setting up a test for the decryption algorithm
    for(i = 0; i < size; i++) {copy[i] = input[i];} copy[size] = 0;
    bool decryptionSuccesfull = true;

    e.encryptCBC(input, size, IV);
    std::cout << "\nEncryption with a key of 256 bits:\n" << input << '\n';
    std::cout << "\n------------------------------------------------------"
                 "------------------------------------------------------\n";
    e.decryptCBC(input, size, IV);
    std::cout << "\nDecryption::\n" << input << '\n';

    e = AES(key192, AESkey::_192);

    e.encryptCBC(input, size, IV);
    std::cout << "\nEncryption with a key of 192 bits:\n" << input << '\n';
    std::cout << "\n------------------------------------------------------"
                 "------------------------------------------------------\n";
    e.decryptCBC(input, size, IV);
    std::cout << "\nDecryption::\n" << input << '\n';

    e = AES(key128, AESkey::_128);

    e.encryptCBC(input, size, IV);
    std::cout << "\nEncryption with a key of 128 bits:\n" << input << '\n';
    std::cout << "\n------------------------------------------------------"
                 "------------------------------------------------------\n";
    e.decryptCBC(input, size, IV);
    std::cout << "\nDecryption::\n" << input << '\n';

    i = 0; // -Testing the decryption process.
    while((decryptionSuccesfull = input[i] == copy[i]) && input[i] != 0) {i++;}
    if(decryptionSuccesfull) std::cout << "\nDecryption successful.\n\n";
    else std::cout << "\nDecryption failure.\n\n";

    return 0;
}

