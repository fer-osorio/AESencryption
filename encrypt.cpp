#include<iostream>
#include<random>
#include<fstream>
#include"Source/Bitmap.hpp"

// Initializing keys with the ones showed in the NIST standard.
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

void set_key(AESkey::Length len); // Not proved to be secure.
void printKey(AESkey::Length len, const char* = NULL, const char* = NULL);

int main(int argc, char *argv[]) {
    char IV[16];
    if(argc > 1) { // Encrypting Bitmap image.
        Bitmap img(argv[1]);
        AES e(key256, AESkey::_256);
        encryptCBC(img, e, IV);
        for(int i = 2; i < argc; i++) {
            img = Bitmap(argv[i]);
            encryptCBC(img, e, IV);
        }
        return 0;
    }

    char buffer[1024], fname[] = "encryption.txt";
    unsigned size = 0, i;
    std::ofstream file(fname);

    set_key(AESkey::_128);
    AES e(key128, AESkey::_128);

    std::cout << "\nWrite the string you want to encrypt. To process the "
                 "string sent the value 'EOF', which you can do by:\n\n"
                 "- Pressing twice the keys CTRL-Z for Windows.\n"
                 "- Pressing twice the keys CTRL-D for Unix and Linux.\n\n";
    if(file.is_open()) {
        while((buffer[size++] = getchar()) != EOF) { // Input from CLI.
            if(size == 1024) {
                e.encryptECB(buffer, size);
                for(i = 0; i < size; i++) file.put(buffer[i]);
                size = 0;
            }
        }
        e.encryptECB(buffer, size);
        for(i = 0; i < size; i++) file.put(buffer[i]);
        file.close();
        printKey(AESkey::_128, "\n\nKey = ", "\n");
        e.saveKey("encryption.key");
    }
    else {
        std::cout << "Could not create output file, terminating the program\n";
        return EXIT_FAILURE;
    }
    /*char input[1025]; // Maximum size 1024 characters without EOF.
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

    // -Setting up a test for the decryption algorithm
    for(i = 0; i < size; i++) {copy[i] = input[i];} copy[size] = 0;
    bool decryptionSuccesfull = true;

    set_key(AESkey::_256);
    AES e(key256, AESkey::_256);
    printKey(AESkey::_256, "\nkey256 = ");

    e.encryptCBC(input, size, IV);
    std::cout << "\nEncryption with a key of 256 bits:\n" << input << '\n';
    std::cout << "\n------------------------------------------------------"
                 "------------------------------------------------------\n";
    e.decryptCBC(input, size, IV);
    std::cout << "\nDecryption::\n" << input << '\n';

    set_key(AESkey::_192);
    e = AES(key192, AESkey::_192);
    printKey(AESkey::_192, "\nkey192 = ");

    e.encryptCBC(input, size, IV);
    std::cout << "\nEncryption with a key of 192 bits:\n" << input << '\n';
    std::cout << "\n------------------------------------------------------"
                 "------------------------------------------------------\n";
    e.decryptCBC(input, size, IV);
    std::cout << "\nDecryption::\n" << input << '\n';

    set_key(AESkey::_128);
    e = AES(key128, AESkey::_128);
    printKey(AESkey::_128, "\nkey128 = ");

    e.encryptCBC(input, size, IV);
    std::cout << "\nEncryption with a key of 128 bits:\n" << input << '\n';
    std::cout << "\n------------------------------------------------------"
                 "------------------------------------------------------\n";
    e.decryptCBC(input, size, IV);
    std::cout << "\nDecryption::\n" << input << '\n';

    i = 0; // -Testing the decryption process.
    while((decryptionSuccesfull = input[i] == copy[i]) && input[i] != 0) {i++;}
    if(decryptionSuccesfull) std::cout << "\nDecryption successful.\n\n";
    else std::cout << "\nDecryption failure.\n\n";*/

    return 0;
}

void set_key(AESkey::Length len) {
    std::random_device dev; std::mt19937 seed(dev());
    std::uniform_int_distribution<std::mt19937::result_type> distribution;
    int i, j;
    intToChar buff;
    switch(len) {
        case AESkey::_128:
            for(i = 0; i < 4; i++) {
                j = i << 2; // j = i*4
                buff.integer = distribution(seed);
                key128[j]   = buff.chars[0];
                key128[j+1] = buff.chars[1];
                key128[j+2] = buff.chars[2];
                key128[j+3] = buff.chars[3];
            }
            break;
        case AESkey::_192:
            for(i = 0; i < 6; i++) {
                j = i << 2; // j = i*4
                buff.integer = distribution(seed);
                key192[j]   = buff.chars[0];
                key192[j+1] = buff.chars[1];
                key192[j+2] = buff.chars[2];
                key192[j+3] = buff.chars[3];
            }
            break;
        case AESkey::_256:
            for(i = 0; i < 8; i++) {
                j = i << 2; // j = i*4
                buff.integer = distribution(seed);
                key256[j]   = buff.chars[0];
                key256[j+1] = buff.chars[1];
                key256[j+2] = buff.chars[2];
                key256[j+3] = buff.chars[3];
            }
            break;
        default:
            throw "Key length not allowed.";
    }
}

void printKey(AESkey::Length len, const char* front, const char* back) {
    int i;
    unsigned char t;
    if(front != NULL) std::cout << front;
    std::cout << '[';
    switch(len) {
        case AESkey::_128:
            for(i = 0; i < 16; i++) {
                t = (unsigned char)key128[i];
                if(i != 0 && (i&3) == 0) std::cout << ',';
                if(t < 16) std::cout << '0';
                printf("%X", t);
            }
            break;
        case AESkey::_192:
            for(i = 0; i < 24; i++) {
                t = (unsigned char)key192[i];
                if(i != 0 && (i&3) == 0) std::cout << ',';
                if(t < 16) std::cout << '0';
                printf("%X", t);
            }
            break;
        case AESkey::_256:
            for(i = 0; i < 32; i++) {
                t = (unsigned char)key256[i];
                if(i != 0 && (i&3) == 0) std::cout << ',';
                if(t < 16) std::cout << '0';
                printf("%X", t);
            }
            break;
    }
    std::cout << ']';
    if(back != NULL) std::cout << back;
}
