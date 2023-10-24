#include"AESkey.hpp"

AESkey::AESkey(const char* const _key, Length len)
: length(len), lenBytes(len >> 3) {
    this->key = new char[this->lenBytes];
    for(int i = 0; i < this->lenBytes; i++) this->key[i] = _key[i];
}

AESkey::AESkey(const AESkey& ak) : length(ak.length), lenBytes(ak.lenBytes) {
    this->key = new char[ak.lenBytes];
    for(int i = 0; i < ak.lenBytes; i++) this->key[i] = ak.key[i];
}

AESkey& AESkey::operator = (const AESkey& ak) {
    if(this != &ak) {
        this->length   = ak.length;
        this->lenBytes = ak.lenBytes;
        if(this->key != NULL) delete[] this->key;
        this->key = new char[ak.lenBytes];
        for(int i = 0; i < ak.lenBytes; i++) this->key[i] = ak.key[i];
    }
    return *this;
}

AESkey::~AESkey() {
    if(this->key != NULL) delete[] this->key;
    this->key = NULL;
}
