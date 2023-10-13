#include<iostream>
#include <fstream>
#include"Source/Bitmap.hpp"

// -Handling the file where the key and the integer necessary for the
class KIV { // creation of the initial vector are stored.
    char kiv[3];
    char key[32];
    int  iv;

    public: KIV(const char* fname) {
        std::ifstream file;
        file.open(fname, std::ios::binary);
        if(file.is_open()) {
            file.read((char*)kiv, 3);
            if(kiv[0] == 'K' && kiv[1] == 'I' && kiv[2] == 'V') {
                file.read((char*)key, 32);
                file.read((char*)&iv, 4);
            } else throw "Not a KIV file.";
        } else throw "Could not open file.";
    }

    int  return_iv()  { return iv; }
    void return_key(char destination[32]) {
        for(int i = 0; i < 32; i++) destination[i] = key[i];
    }
};

int main(int argc, char *argv[]) {
    if(argc > 2) {
        KIV kiv(argv[1]); // Getting the key
        char key[32]; kiv.return_key(key);

        AES_256 e(key);
        Bitmap img(argv[2]);
        decrypt(img, e, kiv.return_iv());
        /*for(int i = 2; i < argc; i++) {
            img = Bitmap(argv[i]);
            encrypt(img, e);
        }*/
        //std::cout << '\n';
        return 0;
    } else {
        std::cout << "\nNot enough arguments passed (at least two). "
                     "Nothing to do.\n\n";
    }
    return 0;
}

