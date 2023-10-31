#include<iostream>
#include<fstream>
#include"Source/Bitmap.hpp"

int main(int argc, char *argv[]) {
    if(argc > 2) {
        AESkey aeskey(argv[1]);
        AES e(aeskey);
        Bitmap img(argv[2]);
        char IV[16];
        aeskey.write_IV(IV);
        decryptCBC(img, e, IV);

        for(int i = 3; i < argc; i++) {
            aeskey = AESkey(argv[i]);
            e = AES(aeskey);
            img = Bitmap(argv[++i]);
            decryptCBC(img, e, IV);
        }
        return EXIT_SUCCESS;
    }
    std::ifstream file;
    char  fname[64], kname[64], buffer[1025];
    unsigned sz = 0;
    std::cout << "Decryption of .txt files.\nWrite the name of the .txt file "
                 "you want to decrypt and then press enter: ";
    while(sz < 64 && (fname[sz++] = getchar()) != '\n') {}
    fname[--sz] = 0;
    file.open(fname);
    if(file.is_open()) {
        std::cout << "Write the name of the .key file where the encryption key "
                 "is saved: ";
        sz = 0;
        while(sz < 64 && (kname[sz++] = getchar()) != '\n') {}
        kname[--sz] = 0;
        AESkey aeskey(kname);
        AES e(aeskey);
        sz = 0;
        while(file.get(buffer[sz++])) {
            if(sz == 1024) {
                buffer[sz] = 0;
                e.decryptECB(buffer, sz);
                std::cout << buffer;
                sz = 0;
            }
        }
        buffer[--sz] = 0;
        e.decryptECB(buffer, sz);
        std::cout << buffer << '\n';
    } else {
        std::cout << "Could not open file...\n";
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

