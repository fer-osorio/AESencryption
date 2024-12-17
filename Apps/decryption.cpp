#include"Settings.hpp"

int main(int argc, char *argv[]) {
    if(argc > 1) {                                                              // -Handling arguments from console
        try {
            setEncryptionObjectFromFile(argv[1]);
        } catch(std::runtime_error& exp) {
            std::cout << "Could not create AES::Cipher object.\n" << exp.what() << '\n';
            return EXIT_FAILURE;
        }
        for(int i = 2; i < argc; i++) decryptFile(argv[i]);
        return EXIT_SUCCESS;
    }
    std::cout <<
    "Hello! I am a program which is particularly good at undoing what my evil\n"
    "encrypter brother does. Feel free to use me to decrypt any.txt or .bmp file\n"
    "you desire. At any moment you can stop me by pressing the keys 'CTRL + C'.\n"
    "Before anything...\n\n";
    runDecryptionProgram();
    return EXIT_SUCCESS;
}
