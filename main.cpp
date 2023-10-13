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
    if(argc > 1) {
        if(argc > 2) std::cout << "\nExcess in the number of arguments. Reading"
                                  " just the first one.\n\n";
        Bitmap img(argv[1]);
        AES_256 e(key256);
        encrypt(img, e);
        std::cout << '\n';
        return 0;
    }

    char input[1025]; // Maximum size 1024 characters without EOS.
    int size = 0;
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

    AES_256 e(key256);
    int iv = e.encryptCBC(input, size);
    std::cout << "\nEncryption::\n" << input << '\n';
    std::cout << "\n------------------------------------------------------"
                 "------------------------------------------------------\n";
    e.decryptCBC(input, size, iv);
    std::cout << "\nDecryption::\n" << input << '\n';

    return 0;
}

