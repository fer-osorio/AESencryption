#include"Settings.hpp"

int main(int argc, const char *argv[]) {
    if(argc > 1) {                                                              // -Handling arguments from console
        try {
            setEncryptionObjectFromFile(argv[1]);
        } catch(std::runtime_error& exp) {
            std::cout << "Could not create AES::Cipher object.\n" << exp.what() << '\n';
            return EXIT_FAILURE;
        }
        for(int i = 2; i < argc; i++) encryptFile(argv[i]);
        return EXIT_SUCCESS;
    }
    std::cout <<
    "Hello! I am a program which is particularly good at encryption BMP images and\n"
    "text files. Feel free to use me  to encrypt any .txt or .bmp file you desire.\n"
    "At any moment you can stop me by pressing the keys 'CTRL+C'.\n\n"
    "Before anything...\n";
    runEncryptionProgram();
    return EXIT_SUCCESS;
}
