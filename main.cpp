#include<iostream>

int main(int argc, char *argv[]) {
     // -KeyExpansion routine example.
    //char key192[] = {0x8E, 0x73, 0xB0, 0xF7, 0xDA, 0x0E, 0x64, 0x52, 0xC8, 0x10, 0xF3, 0x2B,
    //                 0x80, 0x90, 0x79, 0xE5, 0x62, 0xF8, 0xEA, 0xD2, 0x52, 0x2C, 0x6B, 0x7B};
    //char key256[] = {0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE, 0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
    //            0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7, 0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4};
    /*
    char w[216]; // -Key schedule.
    KeyExpansion(key256, 8, w);
    for(int i = 0; i < 240; i++) {
        printf("%X, ", w[i]);
        if((i + 1 & 3) == 0)
            std::cout << '\n';
    }
    std::cout << '\n';
    */

    // -Cipher example.
    char key128[]= {char(0x2B), char(0x7E), char(0x15), char(0x16), char(0x28),
                    char(0xAE), char(0xD2), char(0xA6), char(0xAB), char(0xF7),
                    char(0x15), char(0x88), char(0x09), char(0xCF), char(0x4F),
                    char(0x3C)};
    char Nk = 4;
    int iv;
    Encryption e(key128, Nk);

    /*char Input[] = {char(0x32), char(0x43), char(0xF6), char(0xA8), char(0x88),
                    char(0x5A), char(0x30), char(0x8D), char(0x31), char(0x31),
                    char(0x98), char(0xA2), char(0xE0), char(0x37), char(0x07),
                    char(0x34)};

    e.encryptBlock(Input);
    e.decryptBlock(Input);
    std::cout << '\n';
    e.printState(Input);*/

    char msg[] = "This is a first test of the encryption algorithm\n";
    std::cout << msg;
    iv = e.encrypt(msg, 48);
    std::cout << "Encryption:: " << msg;
    e.decrypt(msg, 48, iv); // -Something is wrong with the decryption.
    std::cout << "Decryption:: " << msg;

    return 0;
}

