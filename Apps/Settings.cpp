#include<fstream>
#include<cstring>
#include<random>
#include"Settings.hpp"
#define BUFFER_SIZE 1025
#define UPPER_BOUND 4097                                                        // -Intended for indices that run through strings. This selection has a reason; it
                                                                                //  is the upper limit for strings representing directories paths
static void cerrMessageBeforeThrow(const char callerFunction[], const char message[]) {
    if(callerFunction == NULL) return;
    std::cerr << "In file Apps/Settings.cpp, function " << callerFunction << ": " << message << '\n';
}

static void cerrMessageBeforeReThrow(const char callerFunction[], const char message[] = "") {
    if(callerFunction == NULL) return;
    std::cerr << "Called from: File Apps/Settings.cpp, function " << callerFunction << " ..."<< message << '\n';
}

namespace Available {
	enum Key_sizes {
		__128,
		__192,
		__256
	};
	const AES::Key::Length KeySizeValues[] = {AES::Key::_128, AES::Key::_192, AES::Key::_256};
	static bool isAvailableKeySizeValue(int t) {
		return
		t == __128 ||
		t == __192 ||
		t == __256;
	}
	enum Operation_modes {
		ecb,
		cbc
	};
	const AES::Key::OperationMode OperationModeValues[] = {AES::Key::ECB, AES::Key::CBC};
	static bool isAvailableOperationModesValue(int t) {
		return
		t == ecb ||
		t == cbc;
	}
};

namespace Options {                                                             // -Name space destined for naming the main process executed by the program
	enum Key_retreaving {                                                       // -We can say each enumeration list all the possibilities for the refereed action
		RetrieveFromFile,
		CreateNew
	};
	static bool isKeyRetreavingValue(int t) {
		return
		t == RetrieveFromFile ||
		t == CreateNew;
	}

    enum Cipher_object {                                                        // -Actions a cipher object can do over a file
        Ciphering,
        Deciphering
    };

	enum Encryption_main_menu {                                                 // -For encryption program, these are the first options are shown to the user
	    encryptFiles,
	    encryptTextFromCLI,
	    saveKey
	};
	static bool isEncryptionMainMenu(int t) {
		return
		t == encryptFiles ||
		t == encryptTextFromCLI ||
		t == saveKey;
	}
};

namespace CLI {                                                                 // -Functions that interact with user through CIL
    static void getLine(const char* message, char* const destination);		    // -Get input string from console. Finish with a line ending '\n'
    static int  retreaveValidOption(const char optionsString[], bool (validOptionCriteria)(int)); // -Force the user to select a valid option
    static void getLineAndRetreaveKeyFromFile();                                // -Retrieve line, interprets it as a file and tries to build key from that file
    static void retreaveKey(Options::Key_retreaving);                           // -Retrieve key accordingly to its argument
    static void getFilesAndCipherAct(Options::Cipher_object);                   // -Get line, interpret it as a sequence of files and try to encrypt/decrypt them
    static void retreaveTexAndEncrypt();                                        // -Gets input from CIL, encrypt and saves it int a text file
};

static int  subStringDelimitedBySpacesOrQuotation(const char* source, const int start, char* destination);
static void setEncryptionObject(AES::Key::Length len, AES::Key::OperationMode op_mode);	// -Not proven to be secure
static void cipherObjectOverFile(const Options::Cipher_object, const char name[]);// -Encrypts or decrypts file of second argument accordingly to the first argument
static void runProgram(const Options::Cipher_object);

static char key256[] = {(char)0x60, (char)0x3D, (char)0xEB, (char)0x10,         // -Initializing keys with the ones showed in the NIST standard.
                        (char)0x15, (char)0xCA, (char)0x71, (char)0xBE,
                        (char)0x2B, (char)0x73, (char)0xAE, (char)0xF0,
                        (char)0x85, (char)0x7D, (char)0x77, (char)0x81,
                        (char)0x1F, (char)0x35, (char)0x2C, (char)0x07,
                        (char)0x3B, (char)0x61, (char)0x08, (char)0xD7,
                        (char)0x2D, (char)0x98, (char)0x10, (char)0xA3,
                        (char)0x09, (char)0x14, (char)0xDF, (char)0xF4};

static char key192[] = {(char)0x8E, (char)0x73, (char)0xB0, (char)0xF7,
                        (char)0xDA, (char)0x0E, (char)0x64, (char)0x52,
                        (char)0xC8, (char)0x10, (char)0xF3, (char)0x2B,
                        (char)0x80, (char)0x90, (char)0x79, (char)0xE5,
                        (char)0x62, (char)0xF8, (char)0xEA, (char)0xD2,
                        (char)0x52, (char)0x2C, (char)0x6B, (char)0x7B};

static char key128[] = {char(0x2B), char(0x7E), char(0x15), char(0x16),
                        char(0x28), char(0xAE), char(0xD2), char(0xA6),
                        char(0xAB), char(0xF7), char(0x15), char(0x88),
                        char(0x09), char(0xCF), char(0x4F), char(0x3C)};

static AES::Key		    mainKey;
static AES::Cipher	    e;
static File::Bitmap	    bmp;
static File::TXT	    txt;


void CLI::getLine(const char* message, char* const destination) {
    std::cout << message << " The maximum amount of characters allowed is " << NAME_MAX_LEN << ":\n";
    std::cin.getline(destination, NAME_MAX_LEN - 1, '\n');
}

int subStringDelimitedBySpacesOrQuotation(const char* source, const int startAt, char* destination) {
    const char thisFunc[] = "int subStringDelimitedBySpacesOrQuotation(const char* source, const int startAt, char* destination)";
    if(source == NULL) {
        cerrMessageBeforeThrow(thisFunc, "Source pointer is a NULL pointer ~~> source == NULL.");
        throw std::invalid_argument("Source pointer is a NULL pointer ~~> source == NULL.\n");
    }
    if(source == NULL) {
        cerrMessageBeforeThrow(thisFunc, "Destination pointer is a NULL pointer ~~> destination == NULL.");
        throw std::invalid_argument("Destination pointer is a NULL pointer ~~> destination == NULL.");
    }
    int  i = 0, j = 0;
    char endingMark = 0;
    for(i = startAt; source[i] == ' ' || source[i] == '\t'; i++) {              // -Ignoring spaces and tabs
        if(i >= UPPER_BOUND) {
            cerrMessageBeforeThrow(thisFunc, "The upper bound for the index looking for the starting token was overreached ~~> i >= UPPER_BOUND.");
            throw std::runtime_error("Upper bound for reached.");
        }
        if(source[i] == 0) {
            cerrMessageBeforeThrow(thisFunc, "End of string reached, starting token not found ~~> source[i] == 0.");
            throw std::runtime_error("End of string reached.");
        }
    }
    endingMark = source[i];
    if(endingMark == '\'' || endingMark == '"') {
        for(i++; source[i] != endingMark; i++) {
            if(i >= UPPER_BOUND) {
                cerrMessageBeforeThrow(thisFunc, "The upper bound for the index looking for the starting token was overreached ~~> i >= UPPER_BOUND.");
                throw std::runtime_error("Upper bound for reached.");
            }
            if(source[i] == 0) {
                cerrMessageBeforeThrow(thisFunc, "End of string reached, starting token not found ~~> source[i] == 0.");
                throw std::runtime_error("End of string reached.");
            }
            destination[j] = source[i];
        }
    } else {
        for(; source[i] != ' ' || source[i] != '\t'; i++) {
            if(i >= UPPER_BOUND) {
                cerrMessageBeforeThrow(thisFunc, "The upper bound for the index looking for the starting token was overreached ~~> i >= UPPER_BOUND.");
                throw std::runtime_error("Upper bound for reached.");
            }
            if(source[i] == 0) {
                cerrMessageBeforeThrow(thisFunc, "End of string reached, starting token not found ~~> source[i] == 0.");
                throw std::runtime_error("End of string reached.");
            }
            destination[j] = source[i];
        }
    }
    destination[j] = 0;
    return i;
}

void setEncryptionObject(AES::Key::Length len, AES::Key::OperationMode op_mode) {
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
    e = AES::Cipher(mainKey);
}

void setEncryptionObjectFromFile(const char _fileName_[]) {
    try {
        mainKey = AES::Key(_fileName_);
    } catch(std::runtime_error&) {
        cerrMessageBeforeReThrow("void setEncryptionObjectFromFile(const char _fileName_[])");
        throw;
    }
    e = AES::Cipher(mainKey);
}

void cipherObjectOverFile(const Options::Cipher_object act,  const char Name[]) {
    const char thisFunc[] = "void Options::file(const char fileName[])";
    bool fileOpenSucces = true;
    File::FileName::Extension ext;
    File::FileName Fname;
    try{
        Fname = File::FileName(Name, true);                                     // -Allowing spaces
    } catch(...){
        cerrMessageBeforeReThrow(thisFunc);
    }
    ext = Fname.getExtension();                                                 // -Recognizing extension.
    switch(ext) {
        case File::FileName::bmp:
            try {
                bmp = File::Bitmap(Name);
            } catch(std::runtime_error& exp) {
                fileOpenSucces = false;
                cerrMessageBeforeReThrow(thisFunc);
                std::cerr << exp.what();
            }
            if(fileOpenSucces) {
                switch(act) {
                    case Options::Cipher_object::Ciphering:
                        std::cout << "\nEncrypting bmp file...\n";
                        encrypt(bmp, e);
                        std::cout << e << '\n';
                        break;
                    case Options::Cipher_object::Deciphering:
                        std::cout << "\nDecrypting bmp file...\n";
                        decrypt(bmp, e);
                        std::cout << e << '\n';
                        break;
                }
            }
            break;
        case File::FileName::txt:
            try {
                txt = File::TXT(Name);
            } catch(std::runtime_error& exp) {
                fileOpenSucces = false;
                cerrMessageBeforeReThrow(thisFunc);
                std::cerr << exp.what();
            }
            if(fileOpenSucces) {
                switch(act) {
                    case Options::Cipher_object::Ciphering:
                        std::cout << "\nEncrypting text file...\n";
                        encrypt(txt, e);
                        std::cout << e << '\n';
                        break;
                    case Options::Cipher_object::Deciphering:
                        std::cout << "\nDecrypting text file...\n";
                        decrypt(txt, e);
                        std::cout << e << '\n';
                        break;
                }
            }
            break;
        case File::FileName::aeskey:
            break;
        case File::FileName::NoExtension:
            break;
        case File::FileName::Unrecognised:
            break;
    }
}

static const char invalidInputMsg[] = "\nInvalid input. Try again.\n";

static const char encryptionMainMenu[] =
"\nPress:\n"
"(0) to encrypt files.\n"
"(1) to encrypt text retrieved from console.\n"
"(2) to save encryption key.\n";

static const char keyRetreavingOptions[] =
"Would you like to:\n"
"(0) Retrieve encryption key from file.\n"
"(1) Let this program generate the encryption key.\n";

static const char selectKeySize[] =
"Select key size. The size is written in bits:\n"
"(0) 128,    (1) 192,    (2) 256\n";

static const char selectOperationMode[] =
"Select operation mode:\n"
"(0) ECB,    (1) CBC\n";

int CLI::retreaveValidOption(const char optionsString[], bool (validOptionCriteria)(int)) { // -Will ask the user for input from a set of options
    int option;
    std::cout << optionsString;
    std::cin >> option;
    getchar();                                                                  // -Will take the "\n" left behind at the moment of press enter
    while(!validOptionCriteria(option)) {                                       // -Validating the option using the criteria specified by 'validOptionCriteria'
        std::cout << invalidInputMsg;                                           //  function. If not valid, it will reaped the process
        std::cout << optionsString;
        std::cin >> option;
        getchar();                                                              // -Will take the "\n" left behind at the moment of press enter
    }
    return option;
}

void CLI::getLineAndRetreaveKeyFromFile() {
    char buffer[NAME_MAX_LEN];
    bool notValidAESkeyFile = true;
    CLI::getLine("Write the name/path of the key we will use for encryption.", buffer);
    while(notValidAESkeyFile) {
        notValidAESkeyFile = false;
        try {                                                                   // -Tries to build a key from file, if fails because the file does not exist, tries
            setEncryptionObjectFromFile(buffer);                                //  again
        }
        catch(std::runtime_error& exp) {
            notValidAESkeyFile = true;
            std::cerr << exp.what() << " Try again.\n";
            CLI::getLine("Write the name/path of the key we will use for encryption.", buffer);
        }
    }
}

void CLI::getFilesAndCipherAct(Options::Cipher_object op) {
    char buffer[UPPER_BOUND];
    char fileName[NAME_MAX_LEN];
    bool subStringExp = false;
    int  inputSize = UPPER_BOUND - 1;
    int  i, j;

    const char enc[] = "encrypt", dec[] = "decrypt";
    const char* opStr;
    if(op == Options::Cipher_object::Ciphering)   opStr = enc;
    if(op == Options::Cipher_object::Deciphering) opStr = dec;
    std::cout <<
    "Write the names/paths of the files you desire to " << opStr << "separated with spaces. Once done, press enter (input must not have spaces and should be\n"
    "at most " << inputSize << " characters long. File names/paths must have at most "<< NAME_MAX_LEN << " characters):\n\n";
    std::cin.getline(buffer, inputSize, '\n');
    for(i = 0, j = 0;; i += j) {                                                // -'for' ends with the break statement on its end (equivalent to a do-while)
        try{
            j = subStringDelimitedBySpacesOrQuotation(&buffer[i], i, fileName);
        } catch(std::runtime_error& exp) {
            std::cout << exp.what();
            subStringExp = true;
        }
        if(!subStringExp) {
            cipherObjectOverFile(op, fileName);
        }
        while(buffer[i] == ' ' || buffer[i] == '\t') if(buffer[i++] == 0) break;// -Terminating 'for'
    }
}

void CLI::retreaveTexAndEncrypt() {
    char*  consoleInput = NULL;
    char*  aux = NULL;
    char   fileName[NAME_MAX_LEN];
    size_t stringSize = 0, k = 0;
    std::ofstream file;
    std::cout <<
    "\nWrite the string you want to encrypt. To process the string sent the value 'EOF', which you can do by:\n\n"
    "- Pressing twice the keys CTRL+Z for Windows.\n"
    "- Pressing twice the keys CTRL+D for Unix and Linux.\n\n";

    consoleInput = new char[UPPER_BOUND];
    while(std::cin.get(consoleInput[stringSize++])) {                           // -Input from CLI.
        if(k == BUFFER_SIZE) {                                                  // -Buffer size exceeded, taking more memory space
            aux = new char[stringSize];
            std::memcpy(aux, consoleInput, stringSize);
            delete[] consoleInput;
            consoleInput = new char[stringSize + BUFFER_SIZE];
            std::memcpy(consoleInput, aux, stringSize);
            delete[] aux;
            k = 0;
        } else { k++; }
    }
    while(stringSize < 16) consoleInput[stringSize++] = 0;                      // -We need at least 16 bytes for AES
    CLI::getLine("Write the name for the .txt file that will contain the encryption.\n", fileName);
    file.open(fileName);
    if(file.is_open()) {
        e.encrypt(consoleInput, stringSize);
        file.write(consoleInput, (std::streamsize)stringSize);
        file.close();
    } else {
        std::cout << "Could not create output file.\n";
    }
    if(consoleInput != NULL) delete[] consoleInput;
    if(aux != NULL)          delete[] aux;
}

void CLI::retreaveKey(Options::Key_retreaving Kr) {                                  // -Retrieving key accordingly to the user's input
    Available::Key_sizes Kz;
    Available::Operation_modes Om;
    switch(Kr) {
        case Options::RetrieveFromFile:
            CLI::getLineAndRetreaveKeyFromFile();
            break;
        case Options::CreateNew:
            Kz = (Available::Key_sizes)CLI::retreaveValidOption(selectKeySize, Available::isAvailableKeySizeValue);
            Om = (Available::Operation_modes)CLI::retreaveValidOption(selectOperationMode, Available::isAvailableOperationModesValue);
            setEncryptionObject(Available::KeySizeValues[Kz], Available::OperationModeValues[Om]);
        break;
    }
}

void runProgram(const Options::Cipher_object op) {
    char keyNameStr[NAME_MAX_LEN];
    bool validName = false;                                                     // -Flags is the given name for the encryption key given by the user is valid
    File::FileName keyName;
    Options::Encryption_main_menu encMainMen;
    Options::Key_retreaving  Kr;

    Kr = (Options::Key_retreaving)CLI::retreaveValidOption(keyRetreavingOptions, Options::isKeyRetreavingValue);    // -Before encryption, the key must obtain
    CLI::retreaveKey(Kr);                                                                                           //  the encryption key

    switch(op) {
        case Options::Cipher_object::Ciphering:
            encMainMen = (Options::Encryption_main_menu)CLI::retreaveValidOption(encryptionMainMenu, Options::isEncryptionMainMenu);// -Asking what we will encrypt
            switch(encMainMen) {
                case Options::Encryption_main_menu::encryptFiles:
                    CLI::getFilesAndCipherAct(Options::Cipher_object::Ciphering);// -Encrypting files passed in a line from CLI
                    break;
                case Options::Encryption_main_menu::encryptTextFromCLI:
                    CLI::retreaveTexAndEncrypt();                               // -Retrieve text from CLI, encrypts and saves the result in a text file
                    break;
                case Options::Encryption_main_menu::saveKey:
                    break;
            }
            CLI::getLine("Assign a name to the key file.", keyNameStr);
            while(!validName) {                                                 // -Validating the name for the key files
                validName = true;
                try{
                    keyName = File::FileName(keyNameStr);
                } catch(std::runtime_error& exp) {
                    validName = false;
                    std::cerr << exp.what();
                    CLI::getLine("Assign a name to the key file.", keyNameStr);
                }
            }
            keyName.writestring(keyNameStr);
            e.saveKey(keyNameStr);
            break;
        case::Options::Cipher_object::Deciphering:
            CLI::getFilesAndCipherAct(Options::Cipher_object::Deciphering);
            break;
    }
}

void encryptFile(const char fileName[]) {
    cipherObjectOverFile(Options::Cipher_object::Ciphering, fileName);
}

void decryptFile(const char fileName[]) {
    cipherObjectOverFile(Options::Cipher_object::Deciphering, fileName);
}

void runEncryptionProgram() {
    runProgram(Options::Cipher_object::Ciphering);
}

void runDecryptionProgram() {
    runProgram(Options::Cipher_object::Deciphering);
}
