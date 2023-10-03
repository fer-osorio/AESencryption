#include<iostream>
#include"AES_256.hpp"

int main(int argc, char *argv[]) {
    char key256[] = {(char)0x60, (char)0x3D, (char)0xEB, (char)0x10,
                     (char)0x15, (char)0xCA, (char)0x71, (char)0xBE,
                     (char)0x2B, (char)0x73, (char)0xAE, (char)0xF0,
                     (char)0x85, (char)0x7D, (char)0x77, (char)0x81,
                     (char)0x1F, (char)0x35, (char)0x2C, (char)0x07,
                     (char)0x3B, (char)0x61, (char)0x08, (char)0xD7,
                     (char)0x2D, (char)0x98, (char)0x10, (char)0xA3,
                     (char)0x09, (char)0x14, (char)0xDF, (char)0xF4};

    /*char Input[] = {char(0x32), char(0x43), char(0xF6), char(0xA8),
                    char(0x88), char(0x5A), char(0x30), char(0x8D),
                    char(0x31), char(0x31), char(0x98), char(0xA2),
                    char(0xE0), char(0x37), char(0x07), char(0x34)};*/
    char input[] = "This is a test for the encryption algorithm.....";
    AES_256 e(key256);
    int iv = e.encrypt(input, 48);
    std::cout << input;
    std::cout << "\n----------------------------------------------------\n";
    e.decrypt(input, 48, iv);
    std::cout << input << '\n';

    return 0;
}

