#include<iostream>
#include<fstream>
#include"Source/File.hpp"

int main(int argc, char *argv[]) {
    File::Bitmap bmp;
    File::TXT txt;
    if(argc > 2) {
        AES::Key aeskey(argv[1]);
        std::cout << "\nIn file decrypt.cpp, function main. aeskey.getOperationMode() = " << aeskey.getOperationMode() << '\n';
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
                break;
            case File::FileName::txt:
                std::cout << "\nDecrypting text file...\n" << std::endl;
                try {
                    txt = File::TXT(argv[2]);
                } catch(const char* err) {
                    std::cout << err;
                }
                decrypt(txt, e);
                break;
            case File::FileName::key:
                break;
            case File::FileName::NoExtension:
                break;
            case File::FileName::Unrecognised:
                break;
        }
        return EXIT_SUCCESS;
    }
    std::ifstream file;
    char  fname[65], kname[65], buffer[1025];
    unsigned sz = 0, i = 0;

    std::cout << "Write the name of the .key file where the encryption key is saved (Maximum size in characters is 64):\n";
    while(sz < 64 && (kname[sz++] = getchar()) != '\n') {}
    kname[--sz] = 0;

    AES::Key aeskey(kname);
    AES::Cipher e(aeskey);
    File::FileName Fname;
    File::FileName::Extension ext;
    sz = 0;

    std::cout << "\nWrite the names/paths of the files you desire to decrypt separated with spaces."
                 "\nOnce done, press enter (input must not have spaces and should be at most 1024"
                 "\ncharacters long. File names/paths must have less than 64 characters):\n\n";
    std::cin.getline(buffer, 1024, '\n');
    while(buffer[i++] != 0) {} // Appending one space at the end of
    buffer[i-1] = ' '; buffer[i] = 0; // the input string.

    for(i = 0; buffer[i] != 0; ++i) {
        if((buffer[i] > 47 && buffer[i] < 58) ||                                // -Naive way of getting a valid name
           (buffer[i] > 64 && buffer[i] < 91) ||
           (buffer[i] > 96 && buffer[i] < 123)||
            buffer[i] == '.' ||
            buffer[i] == '_' ||
            buffer[i] == '-' ||
            buffer[i] == '/' ||
            buffer[i] == '~' ||
            buffer[i] == '\\') {
                fname[sz++] = buffer[i];
        }
        if(buffer[i] == ' ' || buffer[i] == '\t') {
            fname[sz] = 0; sz = 0;
            Fname = File::FileName(fname);
            ext = Fname.getExtension();
            switch(ext) {
                case File::FileName::bmp:
                    std::cout << "\nDecrypting " << fname << "...\n\n";
                    try {
                        bmp = File::Bitmap(fname);
                    } catch(const char* errMsg) {
                        std::cout << errMsg;
                    }
                    decrypt(bmp, e);
                    break;
                case File::FileName::txt:
                    std::cout << "\nDecrypting " << fname << "...\n\n";
                    try {
                        txt = File::TXT(fname);
                    } catch(const char* errMsg) {
                        std::cout << errMsg;
                    }
                    decrypt(txt, e);
                    break;
                case File::FileName::key:
                    break;
                case File::FileName::NoExtension:
                case File::FileName::Unrecognised:
                    std::cout << "Could not handle file. Terminating "
                        "the program with failure status...\n";
                    return EXIT_FAILURE;
            }
        }
    }
    std::cout << "Terminating program with success status...\n";
    return EXIT_SUCCESS;
}
