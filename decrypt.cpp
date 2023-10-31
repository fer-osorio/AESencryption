#include<iostream>
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
    std::cout << "\nNot enough arguments passed (at least two). "
                 "Nothing to do.\n\n";
    return EXIT_SUCCESS;
}

