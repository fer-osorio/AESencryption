#include"AESkey.hpp"
#include<fstream>

AESkey::AESkey(const char* const _key, Length len, OperationMode _opM,
               const char* const _IV)
               :length(len), lenBytes(len >> 3), opM(_opM) {
    this->key = new char[this->lenBytes];
    for(int i = 0; i < this->lenBytes; i++) this->key[i] = _key[i];
    if(_IV != NULL) for(int i = 0; i < 16; i++) this->IV[i] = _IV[i];
}

AESkey::AESkey(const AESkey& ak)
    :length(ak.length), lenBytes(ak.lenBytes), opM(ak.opM) {
    this->key = new char[ak.lenBytes];
    for(int i = 0; i < ak.lenBytes; i++) this->key[i] = ak.key[i];
    if(ak.opM == CBC)   // Without CBC, copying IV is pointless.
        for(int i = 0; i < 16; i++) this->IV[i] = ak.IV[i];
}

AESkey& AESkey::operator = (const AESkey& ak) {
    if(this != &ak) {
        this->length   = ak.length;
        this->lenBytes = ak.lenBytes;
        if(this->key != NULL) delete[] this->key;
        this->key = new char[ak.lenBytes];
        for(int i = 0; i < ak.lenBytes; i++) this->key[i] = ak.key[i];
        if(ak.opM == CBC)   // Without CBC, copying IV is pointless.
            for(int i = 0; i < 16; i++) this->IV[i] = ak.IV[i];
    }
    return *this;
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
