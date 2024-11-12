#include<iostream>
#include<fstream>
#include"../Source/File.hpp"

#define BUFFER_SIZE 1025

static void getFileNameStringFromConsole(const char* message, char* const destination);

static AES::Key mainKey;

int main(int argc, char *argv[]) {
    File::Bitmap bmp;
    File::TXT txt;
    if(argc > 2) {
        AES::Key aeskey(argv[1]);
        AES::Cipher e(aeskey);
        File::FileName fname(argv[2]);                                          // -Recognizing extension.
        File::FileName::Extension ext = fname.getExtension();
        switch(ext) {
            case File::FileName::bmp:
                std::cout << "\nDecrypting bmp file...\n" << std::endl;
                try {
                    bmp = File::Bitmap(argv[2]);
                } catch(const char* err) {
                    std::cout << err;
                }
                decrypt(bmp, e);
                std::cout << e << '\n';
                break;
            case File::FileName::txt:
                std::cout << "\nDecrypting text file...\n" << std::endl;
                try {
                    txt = File::TXT(argv[2]);
                } catch(const char* err) {
                    std::cout << err;
                }
                decrypt(txt, e);
                std::cout << e << '\n';
                break;
            case File::FileName::aeskey:
                break;
            case File::FileName::NoExtension:
                break;
            case File::FileName::Unrecognised:
                break;
        }
        return EXIT_SUCCESS;
    }
    std::ifstream file;
    char  fileName[NAME_MAX_LEN], buffer[BUFFER_SIZE];
    unsigned i = 0, stringSize = 0;
    File::FileName::Extension ext;                                              // -Recognizing extension of the file
    File::FileName Fname;                                                       // -Used mainly for the recognition of extensions

    bool notValidAESkeyFile = true;
    while(notValidAESkeyFile) {
        getFileNameStringFromConsole("Write the name/path of the key we will use for decryption.", fileName);
        notValidAESkeyFile = false;
        try { mainKey = AES::Key(fileName); }
        catch(const char* exp) {
            notValidAESkeyFile = true;
            std::cerr << exp << " Try again.\n";
            getFileNameStringFromConsole("Write the name/path of the key we will use for decryption.", fileName);
        }
    }

    AES::Cipher e(mainKey);
    int inputSize = BUFFER_SIZE - 1;
    std::cout <<
    "Write the names/paths of the files you desire to decrypt separated with spaces. Once done, press enter (input must not have spaces and should be\n"
    "at most " << inputSize << " characters long. File names/paths must have at most "<< NAME_MAX_LEN << " characters):\n\n";
    std::cin.getline(buffer, inputSize, '\n');
    for(i = 0;;) {                                                              // -For ends with the break statement on its end (this is equivalent to a do-while)
        while(buffer[i] == ' ' || buffer[i] == '\t') { i++; }                   // -Consuming spaces and tabs till we find any other character
        if((buffer[i] > 47 && buffer[i] < 58) ||                                // -Naive way of getting a valid name using ASCII code. First decimal digits
           (buffer[i] > 64 && buffer[i] < 91) ||                                // -Then Upper case letters
           (buffer[i] > 96 && buffer[i] < 123)||                                // -Followed by lower case letters
            buffer[i] == '.' ||                                                 // -And finally special symbols
            buffer[i] == '_' ||                                                 // ...
            buffer[i] == '-' ||                                                 // ...
            buffer[i] == '/' ||                                                 // ...
            buffer[i] == '~' ||                                                 // ...
            buffer[i] == '\\') {                                                // ...
                fileName[stringSize++] = buffer[i++];                           // -While the character is valid and while we do not encounter a space or a tab,
        }                                                                       //  we will suppose is a name/path a file
        if(buffer[i] == ' ' || buffer[i] == '\t' || buffer[i] == 0) {           // -We encounter a space, tab or 0; starting the encryption process
            fileName[stringSize] = 0;
            stringSize = 0;
            Fname = File::FileName(fileName);
            ext = Fname.getExtension();
            switch(ext) {
                case File::FileName::bmp:
                    std::cout << "\nDecrypting " << fileName << "...\n\n";
                    try {
                        bmp = File::Bitmap(fileName);
                    } catch(const char* errMsg) {
                        std::cout << errMsg;
                    }
                    std::cout << bmp << "\n\n";
                    decrypt(bmp, e);
                    std::cout << e << '\n';
                    break;
                case File::FileName::txt:
                    std::cout << "\nDecrypting " << fileName << "...\n\n";
                    try {
                        txt = File::TXT(fileName);
                    } catch(const char* errMsg) {
                        std::cout << errMsg;
                    }
                    decrypt(txt, e);
                    std::cout << e << '\n';
                    break;
                case File::FileName::aeskey:
                    break;
                case File::FileName::NoExtension:
                case File::FileName::Unrecognised:
                    std::cout << "Could not handle input string. Terminating with failure status...\n";
                    return EXIT_FAILURE;
            }
        }
        if(buffer[i] == 0) break;                                               // -Terminating 'for'
    }
    std::cout << "Terminating program with success status...\n";
    return EXIT_SUCCESS;
}

void getFileNameStringFromConsole(const char* message, char* const destination) {
    std::cout << message << " The maximum amount of characters allowed is " << NAME_MAX_LEN << ":\n";
    std::cin.getline(destination, NAME_MAX_LEN - 1, '\n');
}
