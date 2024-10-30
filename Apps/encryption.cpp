#include<iostream>
#include<random>
#include<fstream>
#include<cstring>
#include"../Source/File.hpp"

#define BUFFER_SIZE 1025

char key256[] = {(char)0x60, (char)0x3D, (char)0xEB, (char)0x10,                // -Initializing keys with the ones showed in the NIST standard.
                 (char)0x15, (char)0xCA, (char)0x71, (char)0xBE,
                 (char)0x2B, (char)0x73, (char)0xAE, (char)0xF0,
                 (char)0x85, (char)0x7D, (char)0x77, (char)0x81,
                 (char)0x1F, (char)0x35, (char)0x2C, (char)0x07,
                 (char)0x3B, (char)0x61, (char)0x08, (char)0xD7,
                 (char)0x2D, (char)0x98, (char)0x10, (char)0xA3,
                 (char)0x09, (char)0x14, (char)0xDF, (char)0xF4};

char key192[] = {(char)0x8E, (char)0x73, (char)0xB0, (char)0xF7,
                 (char)0xDA, (char)0x0E, (char)0x64, (char)0x52,
                 (char)0xC8, (char)0x10, (char)0xF3, (char)0x2B,
                 (char)0x80, (char)0x90, (char)0x79, (char)0xE5,
                 (char)0x62, (char)0xF8, (char)0xEA, (char)0xD2,
                 (char)0x52, (char)0x2C, (char)0x6B, (char)0x7B};

char key128[]= {char(0x2B), char(0x7E), char(0x15), char(0x16),
                char(0x28), char(0xAE), char(0xD2), char(0xA6),
                char(0xAB), char(0xF7), char(0x15), char(0x88),
                char(0x09), char(0xCF), char(0x4F), char(0x3C)};

static AES::Key mainKey;
static AES::Key::Length KeySizes[3] = {AES::Key::Length::_128, AES::Key::Length::_192, AES::Key::Length::_192};
static AES::Key::OperationMode AvailableOpMode[3] = {AES::Key::OperationMode::ECB, AES::Key::OperationMode::CBC};

static void set_mainKey(AES::Key::Length len, AES::Key::OperationMode op_mode); // -Not proved to be secure.

static void getFileNameStringFromConsole(const char* message, char* const destination);

int main(int argc, char *argv[]) {
    File::Bitmap bmp;
    File::TXT txt;
    AES::Cipher e;
    File::FileName::Extension ext;                                              // -Recognizing extension of the file
    if(argc == 3) {                                                             // -Encrypting File.
        try {
            mainKey = AES::Key(argv[1]);                                        // -Passing name of key file
        } catch(const char* exp) {
            std::cout << "Could not create AES::Key object.\n" << exp;
            return EXIT_FAILURE;
        }
        File::FileName fname(argv[2]);                                          // -Recognizing extension.
        ext = fname.getExtension();
        e = AES::Cipher(mainKey);                                               // -Passing name of key file
        switch(ext) {
            case File::FileName::bmp:
                std::cout << "\nEncrypting bmp file...\n\n";
                try {
                    bmp = File::Bitmap(argv[2]);
                } catch(const char* errMsg) {
                    std::cout << errMsg;
                }
                encrypt(bmp, e);
                e.saveKey(argv[1]);                                             // -We cant ensure the operation mode in key file is the same as the operation mode
                std::cout << e << '\n';                                         //  used for encryption, so we need to update the key file.
                break;
            case File::FileName::txt:
                std::cout << "\nEncrypting text file...\n\n";
                try {
                    txt = File::TXT(argv[2]);
                } catch(const char* errMsg) {
                    std::cout << errMsg;
                }
                encrypt(txt, e);
                e.saveKey(argv[1]);                                             // -We cant ensure the operation mode in key file is the same as the operation mode
                std::cout << e << '\n';                                         //  used for encryption, so we need to update the key file.
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

    unsigned stringSize = 0, i = 0;
    char* consoleInput = NULL;
    char* aux = NULL;                                                           // -Auxiliary
    char  buffer[BUFFER_SIZE], fileName[NAME_MAX_LEN+1], keyNameStr[NAME_MAX_LEN+1];
    int option, keyRetreavingOp, keySizeOp, OperationModeOp;                    // -Op stands for option
    File::FileName keyName;
    File::FileName Fname;                                                       // -Used mainly for the recognition of extensions
    std::ofstream  file;

    std::cout << "\nPress:\n"
        "(1) to encrypt files.\n"
        "(2) to encrypt text retrieved from console.\n"
        "(3) to generate and save encryption key.\n";
    std::cin >> option;
    getchar();                                                                  // -Will take the "\n" left behind at the moment of press enter

    while(option < 1 || option > 3) {
        std::cout << "\nInvalid input. Try again.\n";
        std::cout << "\nPress:\n"
             "(1) to encrypt files.\n"
             "(2) to encrypt text retrieved from console.\n"
             "(3) to generate and save encryption key.\n";
        std::cin >> option;
        getchar();                                                              // -Will take the "\n" left behind at the moment of press enter
    }

    if(option != 3) {
        std::cout << "Would you like to:\n"
            "(1) Retrieve encryption key from file.\n"
            "(2) Let this program generate the encryption key.\n";
        std::cin >> keyRetreavingOp;
        getchar();                                                              // -Will take the "\n" left behind at the moment of press enter
        while(keyRetreavingOp < 1 || keyRetreavingOp > 2) {
            std::cout << "\nInvalid input. Try again.\n";
            std::cout << "Would you like to:\n"
                "(1) Retrieve encryption key from file.\n"
                "(2) Let this program generate the encryption key.\n";
            std::cin >> keyRetreavingOp;
            getchar();                                                          // -Will take the "\n" left behind at the moment of press enter
        }
        if(keyRetreavingOp == 1) {
            bool notValidAESkeyFile = true;
            while(notValidAESkeyFile) {
                getFileNameStringFromConsole("Write the name/path of the key we will use for encryption.", fileName);
                notValidAESkeyFile = false;
                try { mainKey = AES::Key(fileName); }
                catch(const char* exp) {
                    notValidAESkeyFile = true;
                    std::cerr << exp << " Try again.\n";
                    getFileNameStringFromConsole("Write the name/path of the key we will use for encryption.", fileName);
                }
            }
        } else {
            std::cout << "Select key size. The size is written in bits:\n"
                "(1) 128,    (2) 192,    (3) 256\n";
            std::cin >> keySizeOp;
            getchar();                                                          // -Will take the "\n" left behind at the moment of press enter
            while(keySizeOp < 1 || keySizeOp > 2) {
                std::cout << "\nInvalid input. Try again.\n";
                std::cout << "Select key size. The size is written in bits:\n"
                    "(1) 128,    (2) 192,    (3) 256\n";
                std::cin >> keySizeOp;
                getchar();                                                      // -Will take the "\n" left behind at the moment of press enter
            }
            std::cout << "Select operation mode:\n"
                "(1) ECB,    (2) CBC\n";
            std::cin >> OperationModeOp;
            getchar();                                                          // -Will take the "\n" left behind at the moment of press enter
            while(OperationModeOp < 1 || OperationModeOp > 3) {
                std::cout << "\nInvalid input. Try again.\n";
                std::cout << "Select operation mode:\n"
                    "(1) ECB,    (2) CBC\n";
                std::cin >> OperationModeOp;
                getchar();                                                      // -Will take the "\n" left behind at the moment of press enter
            }
            set_mainKey(KeySizes[keySizeOp - 1], AvailableOpMode[OperationModeOp-1]);
        }
        e = AES::Cipher(mainKey);
        if(option == 1) {
            int inputSize = BUFFER_SIZE - 1;
            std::cout <<
            "Write the names/paths of the files you desire to encrypt separated with spaces. Once done, press enter (input must not have spaces and should be\n"
            "at most " << inputSize << " characters long. File names/paths must have at most "<< NAME_MAX_LEN << " characters):\n\n";
            std::cin.getline(buffer, inputSize, '\n');
            /*while(buffer[i++] != 0) {}                                        // Appending one space at the end of the input string.
            buffer[i-1] = ' '; buffer[i] = 0;*/
            for(i = 0;;) {                                                      // -For ends with the break statement on its end (this is equivalent to a do-while)
                while(buffer[i] == ' ' || buffer[i] == '\t') { i++; }           // -Consuming spaces and tabs till we find any other character
                if((buffer[i] > 47 && buffer[i] < 58) ||                        // -Naive way of getting a valid name using ASCII code. First decimal digits
                   (buffer[i] > 64 && buffer[i] < 91) ||                        // -Then Upper case letters
                   (buffer[i] > 96 && buffer[i] < 123)||                        // -Followed by lower case letters
                    buffer[i] == '.' ||                                         // -And finally special symbols
                    buffer[i] == '_' ||                                         // ...
                    buffer[i] == '-' ||                                         // ...
                    buffer[i] == '/' ||                                         // ...
                    buffer[i] == '~' ||                                         // ...
                    buffer[i] == '\\') {                                        // ...
                        fileName[stringSize++] = buffer[i++];                   // -While the character is valid and while we do not encounter a space or a tab,
                }                                                               //  we will suppose is a name/path a file
                if(buffer[i] == ' ' || buffer[i] == '\t' || buffer[i] == 0) {   // -We encounter a space, tab or 0; starting the encryption process
                    fileName[stringSize] = 0;
                    //std::cout << "fileName = " << fileName << ", size = " << stringSize << '\n'; // -Debugging purposes
                    stringSize = 0;
                    Fname = File::FileName(fileName);
                    ext = Fname.getExtension();
                    switch(ext) {
                        case File::FileName::bmp:
                            std::cout << "\nEncrypting " << fileName << "...\n\n";
                            try {
                                bmp = File::Bitmap(fileName);
                            } catch(const char* errMsg) {
                                std::cout << errMsg;
                            }
                            std::cout << bmp << "\n\n";
                            encrypt(bmp, e);
                            std::cout << e << '\n';
                            break;
                        case File::FileName::txt:
                            std::cout << "\nEncrypting " << fileName << "...\n\n";
                            try {
                                txt = File::TXT(fileName);
                            } catch(const char* errMsg) {
                                std::cout << errMsg;
                            }
                            encrypt(txt, e);
                            std::cout << e << '\n';
                            break;
                        case File::FileName::key:
                            break;
                        case File::FileName::NoExtension:
                        case File::FileName::Unrecognised:
                            std::cout << "Could not handle input string. Terminating with failure status...\n";
                            return EXIT_FAILURE;
                    }
                }
                if(buffer[i] == 0) break;                                       // -Terminating 'for'
            }
            getFileNameStringFromConsole("Assign a name to the key file.", keyNameStr);
            e.saveKey(keyNameStr);
            std::cout << "Terminating program with success status...\n";
            return EXIT_SUCCESS;
        } else {
            consoleInput = new char[BUFFER_SIZE];
            stringSize = 0;
            std::cout << "\nWrite the string you want to encrypt. To process the string sent the value 'EOF', which you can do by:\n\n"
                         "- Pressing twice the keys CTRL+Z for Windows.\n"
                         "- Pressing twice the keys CTRL+D for Unix and Linux.\n\n";
            while(std::cin.get(consoleInput[stringSize++])) {                   // -Input from CLI.
                if(i == BUFFER_SIZE) {                                          // -Buffer size exceeded, taking more memory space
                    aux = new char[stringSize];
                    std::memcpy(aux, consoleInput, stringSize);
                    delete[] consoleInput;
                    consoleInput = new char[stringSize + BUFFER_SIZE];
                    std::memcpy(consoleInput, aux, stringSize);
                    delete[] aux;
                    i = 0;
                } else { i++; }
            }
            while(stringSize < 16) consoleInput[stringSize++] = 0;              // -We need at least 16 bytes for AES
            getFileNameStringFromConsole("Write the name for the .txt file that will contain the encryption.\n", fileName);
            file.open(fileName);
            if(file.is_open()) {
                e.encryptECB(consoleInput, stringSize);
                file.write(consoleInput, stringSize);
                file.close();
                getFileNameStringFromConsole("Write the name for the encryption key file.\n", keyNameStr);
                e.saveKey(keyNameStr);
                std::cout << "\nTerminating program with success status...\n";
                return EXIT_SUCCESS;
            } else {
                std::cout << "Could not create output file, terminating the program with failure status...\n";
                return EXIT_FAILURE;
            }
        }
    } else {
        std::cout << "Select key size. The size is written in bits:\n"
            "(1) 128,    (2) 192,    (3) 256\n";
        std::cin >> keySizeOp;
        getchar();                                                              // -Will take the "\n" left behind at the moment of press enter
        while(keySizeOp < 1 || keySizeOp > 2) {
            std::cout << "\nInvalid input. Try again.\n";
            std::cout << "Select key size. The size is written in bits:\n"
                "(1) 128,    (2) 192,    (3) 256\n";
            std::cin >> keySizeOp;
            getchar();                                                          // -Will take the "\n" left behind at the moment of press enter
        }
        std::cout << "Select operation mode:\n"
            "(1) ECB,    (2) CBC\n";
        std::cin >> OperationModeOp;
        getchar();                                                              // -Will take the "\n" left behind at the moment of press enter
        while(OperationModeOp < 1 || OperationModeOp > 2) {
            std::cout << "\nInvalid input. Try again.\n";
            std::cout << "Select operation mode:\n"
                "(1) ECB,    (2) CBC\n";
            std::cin >> OperationModeOp;
            getchar();                                                          // -Will take the "\n" left behind at the moment of press enter
        }
        set_mainKey(KeySizes[keySizeOp - 1], AvailableOpMode[OperationModeOp-1]);
        getFileNameStringFromConsole("Write the name you want to assign to the key file.", fileName);
        mainKey.save(fileName);
    }
    if(consoleInput != NULL) delete[] consoleInput;
    if(aux != NULL)          delete[] aux;
    std::cout << "Terminating program with success status...\n";
    return EXIT_SUCCESS;
}

void set_mainKey(AES::Key::Length len, AES::Key::OperationMode op_mode) {
    std::random_device dev; std::mt19937 seed(dev());
    std::uniform_int_distribution<std::mt19937::result_type> distribution;      // -Random number with uniform distribution
    int i, j;
    union { int integer; char chars[4]; } buff;                                 // -Anonymous union. Casting from 32 bits integer to four chars
    switch(len) {
        case AES::Key::_128:
            for(i = 0; i < 4; i++) {
                j = i << 2;                                                     // -j = i*4
                buff.integer = distribution(seed);                              // -Taking a random 32 bits integer to divide it into four bytes
                key128[j]   = buff.chars[0];
                key128[j+1] = buff.chars[1];
                key128[j+2] = buff.chars[2];
                key128[j+3] = buff.chars[3];
            }
            mainKey = AES::Key(key128, len, op_mode);
            break;
        case AES::Key::_192:
            for(i = 0; i < 6; i++) {
                j = i << 2;                                                     // -j = i*4
                buff.integer = distribution(seed);                              // -Taking a random 32 bits integer to divide it into four bytes
                key192[j]   = buff.chars[0];
                key192[j+1] = buff.chars[1];
                key192[j+2] = buff.chars[2];
                key192[j+3] = buff.chars[3];
            }
            mainKey = AES::Key(key192, len, op_mode);
            break;
        case AES::Key::_256:
            for(i = 0; i < 8; i++) {
                j = i << 2;                                                     // -j = i*4
                buff.integer = distribution(seed);                              // -Taking a random 32 bits integer to divide it into four bytes
                key256[j]   = buff.chars[0];
                key256[j+1] = buff.chars[1];
                key256[j+2] = buff.chars[2];
                key256[j+3] = buff.chars[3];
            }
            mainKey = AES::Key(key256, len, op_mode);
            break;
    }
}

void getFileNameStringFromConsole(const char* message, char* const destination) {
    std::cout << message << " The maximum amount of characters allowed is " << NAME_MAX_LEN << ":\n";
    std::cin.getline(destination, NAME_MAX_LEN - 1, '\n');
}
