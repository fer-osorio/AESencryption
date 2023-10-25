#include<iostream>
#include <fstream>
#include"Source/Bitmap.hpp"

// -Handling the file where the key and the integer necessary for the
class KIV { // creation of the initial vector are stored.
    char kiv[3];  // Identifier
    char key[32]; // Cryptographic key
    int  iv;      // int for the construction of the initial vector

    public: KIV(const char* fname) : kiv{0,0,0}, key{0,0,0}, iv(0) {
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

    KIV(const KIV& kivObj) : kiv{0,0,0}, key{0,0,0}, iv(0) {
        this->kiv[0] = kivObj.kiv[0];
        this->kiv[1] = kivObj.kiv[1];
        this->kiv[2] = kivObj.kiv[2];

        for(int i = 0; i < 32;i++) this->key[i] = kivObj.key[i];

        this->iv = kivObj.iv;
    }

    KIV& operator = (const KIV& kivObj) {
        if(this != &kivObj) { // Guarding against kibObj = kibObj
            this->kiv[0] = kivObj.kiv[0];
            this->kiv[1] = kivObj.kiv[1];
            this->kiv[2] = kivObj.kiv[2];

            for(int i = 0; i < 32;i++) this->key[i] = kivObj.key[i];

            this->iv = kivObj.iv;
        }
        return *this;
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

        AES_256 e(key, AESkey::_256);
        Bitmap img(argv[2]);
        decrypt(img, e, kiv.return_iv());

        for(int i = 3; i < argc; i++) {
            kiv = KIV(argv[i]);
            kiv.return_key(key);
            e = AES_256(key, AESkey::_256);
            img = Bitmap(argv[++i]);
            decrypt(img, e, kiv.return_iv());
        }
        return 0;
    } else {
        std::cout << "\nNot enough arguments passed (at least two). "
                     "Nothing to do.\n\n";
    }
    return 0;
}

