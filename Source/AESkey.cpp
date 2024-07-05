#include"AESkey.hpp"
#include<fstream>

AESkey::AESkey(const char* const _key, Length len, OperationMode _opM, const char* const _IV): length(len), lenBytes((unsigned)len >> 3), opM(_opM) {
    this->key = new char[this->lenBytes];
    for(unsigned i = 0; i < this->lenBytes; i++) this->key[i] = _key[i];
    if(_IV != NULL) for(int i = 0; i < 16; i++) this->IV[i] = _IV[i];
}

AESkey::AESkey(const AESkey& ak):length(ak.length), lenBytes(ak.lenBytes), opM(ak.opM) {
    unsigned i;
    this->key = new char[ak.lenBytes];
    for(i = 0; i < ak.lenBytes; i++) this->key[i] = ak.key[i];
    if(ak.opM == CBC)   // Without CBC, copying IV is pointless.
        for(i = 0; i < 16; i++) this->IV[i] = ak.IV[i];
}

AESkey& AESkey::operator = (const AESkey& ak) {
    if(this != &ak) {
        unsigned i;
        this->length   = ak.length;
        this->lenBytes = ak.lenBytes;
        if(this->key != NULL) delete[] this->key;
        this->key = new char[ak.lenBytes];
        for(i = 0; i < ak.lenBytes; i++) this->key[i] = ak.key[i];
        if(ak.opM == CBC)   // Without CBC, copying IV is pointless.
            for(i = 0; i < 16; i++) this->IV[i] = ak.IV[i];
    }
    return *this;
}

AESkey::AESkey(const char*const fname) : length(_128), lenBytes(16), opM(ECB) {
    char AESKEY[6];
    char op_M[3];
    short len;
    std::ifstream file;
    file.open(fname, std::ios::binary);
    if(file.is_open()) {
        file.read((char*)AESKEY, 6);
        if(AESKEY[0] == 'A' || AESKEY[1] == 'E' || AESKEY[2] == 'S' ||
           AESKEY[3] == 'K' || AESKEY[4] == 'E' || AESKEY[5] == 'Y') {
                file.read((char*)op_M, 3); // -Determining operation mode
                if(op_M[0]=='E' && op_M[1]=='C' && op_M[2]=='B')
                    this->opM = ECB;
                else if(op_M[0]=='C' && op_M[1]=='B' && op_M[2]=='C')
                    this->opM = CBC;
                else if(op_M[0]=='C' && op_M[1]=='F' && op_M[2]=='B')
                    this->opM = CFB;
                else if(op_M[0]=='O' && op_M[1]=='F' && op_M[2]=='B')
                    this->opM = OFB;
                else if(op_M[0]=='C' && op_M[1]=='T' && op_M[2]=='R')
                    this->opM = CTR;
                else throw "Could not recognize operation mode...";

                file.read((char*)&len, 2); // -Reading key length
                if(len == 128 || len == 192 || len == 256)
                    this->length = (Length)len;
                else throw "Key length not allowed...";
                this->lenBytes = (unsigned)len >> 3;

                key = new char[lenBytes]; // -Reading key
                file.read(key, lenBytes);

                // -In CBC case, reading IV.
                if(this->opM == CBC) file.read((char*)IV, 16);
           } else {
                throw "Not a valid .aeskey file...";
           }
    } else {
        throw "Could not open the file...";
    }
}

AESkey::~AESkey() {
    if(this->key != NULL) delete[] this->key;
    this->key = NULL;
}

void AESkey::save(const char* const fname) const {
    const char* aeskey = "AESKEY"; // File type.
    const char* op_mode;
    switch(this->opM) { // -Operation mode.
        case ECB:
            op_mode = "ECB";
            break;
        case CBC:
            op_mode = "CBC";
            break;
        case CFB:
            op_mode = "CFB";
            break;
        case OFB:
            op_mode = "OFB";
            break;
        case CTR:
            op_mode = "CTR";
            break;
        default:
            throw "Could not recognize operation mode...";
    }
    std::ofstream file;
    file.open(fname, std::ios::binary);
    if(file.is_open()) {
        file.write(aeskey,  6);         // -File type
        file.write(op_mode, 3);         // -Operation mode
        file.write((char*)&length, 2);  // -Key length in bits
        file.write(key, lenBytes);      // -Key
        if(this->opM == CBC)           // -If CBC, writes initial vector
            file.write(this->IV, 16);
    } else {
        throw "File could not be written.";
    }
}

