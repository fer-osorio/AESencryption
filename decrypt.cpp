#include<iostream>
#include<fstream>
#include"Source/Bitmap.hpp"
#include"Source/TXT.hpp"

int main(int argc, char *argv[]) {
    Bitmap bmp;
    TXT    txt;
    if(argc > 2) {
        AESkey aeskey(argv[1]);
        AES e(aeskey);
        FileName fname(argv[2]); // -Recognizing extension.
        FileName::Extension ext = fname.getExtension();
        switch(ext) {
            case FileName::bmp:
                std::cout << "\nDecrypting text file...\n" << std::endl;
                try {
                    bmp = Bitmap(argv[2]);
                } catch(const char* err) {
                    std::cout << err;
                }
                decryptCBC(bmp, e);
                break;
            case FileName::txt:
                std::cout << "\nDecrypting text file...\n" << std::endl;
                try {
                    txt = TXT(argv[2]);
                } catch(const char* err) {
                    std::cout << err;
                }
                decryptCBC(txt, e);
                break;
            case FileName::key:
                break;
            case FileName::NoExtension:
                break;
            case FileName::Unrecognised:
                break;
        }
        return EXIT_SUCCESS;
    }
    std::ifstream file;
    char  fname[64], kname[64], buffer[1025];
    unsigned sz = 0, i = 0;

    std::cout << "Write the name of the .key file where the encryption key "
                 "is saved:\n ";
    while(sz < 64 && (kname[sz++] = getchar()) != '\n') {}
    kname[--sz] = 0;

    AESkey aeskey(kname);
    AES e(aeskey);
    FileName Fname;
    FileName::Extension ext;
    sz = 0;

    std::cout << "\nWrite the names/paths of the files you desire to decrypt separated with spaces."
                 "\nOnce done, press enter (input must not have spaces and should be at most 1024"
                 "\ncharacters long. File names/paths must have less than 64 characters):\n\n";
        std::cin.getline(buffer, 1024, '\n');
        while(buffer[i++] != 0) {} // Appending one space at the end of
        buffer[i-1] = ' '; buffer[i] = 0; // the input string.

        for(i = 0; buffer[i] != 0; ++i) {
            if((buffer[i] > 47 && buffer[i] < 58) || // -Naive way of getting a
               (buffer[i] > 64 && buffer[i] < 91) || //  valid name.
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
                Fname = FileName(fname);
                ext = Fname.getExtension();
                switch(ext) {
                    case FileName::bmp:
                        std::cout << "\nDecrypting " << fname << "...\n\n";
                        try {
                            bmp = Bitmap(fname);
                        } catch(const char* errMsg) {
                            std::cout << errMsg;
                        }
                        decryptCBC(bmp, e);
                        break;
                    case FileName::txt:
                        std::cout << "\nDecrypting " << fname << "...\n\n";
                        try {
                            txt = TXT(fname);
                        } catch(const char* errMsg) {
                            std::cout << errMsg;
                        }
                        decryptECB(txt, e);
                        break;
                    case FileName::key:
                        break;
                    case FileName::NoExtension:
                    case FileName::Unrecognised:
                        std::cout << "Could not handle file. Terminating "
                            "the program with failure status...\n";
                        return EXIT_FAILURE;
                }
            }
        }
        std::cout << "Terminating program with success status...\n";
        return EXIT_SUCCESS;

    return EXIT_SUCCESS;
}

