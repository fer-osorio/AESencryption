#include"../../include/AESencryption.hpp"
#include"../data-encryption/AES/AES.h"
#include"../data-encryption/operation_modes/operation_modes.h"

using namespace AESencryption;

Cipher::Cipher() {
    this->keyExpansion = new uint8_t[this->keyExpLen];
    for(int i = 0; i < this->keyExpLen; i++) this->keyExpansion[i] = 0;         // -Since the key constitutes of just zeros, key expansion is also just zeros
}

Cipher::Cipher(const Key& k) :key(k), Nk((int)k.getLenBytes() >> 2), Nr(Nk+6), keyExpLen((Nr+1)<<4) {
    this->buildKeyExpansion();
}

Cipher::Cipher(const Cipher& a) : key(a.key), Nk(a.Nk), Nr(a.Nr), keyExpLen(a.keyExpLen) {
    this->keyExpansion = new uint8_t[(unsigned)a.keyExpLen];
    for(int i = 0; i < a.keyExpLen; i++) this->keyExpansion[i] = a.keyExpansion[i];
}

Cipher::~Cipher() {
    if(keyExpansion != NULL) delete[] keyExpansion;
    keyExpansion = NULL;
}

Cipher& Cipher::operator = (const Cipher& a) {
    if(this != &a) {
        this->key = a.key;
        if(this->keyExpLen != a.keyExpLen) {
            this->Nk = a.Nk;
            this->Nr = a.Nr;
            this->keyExpLen = a.keyExpLen;
            if(this->keyExpansion != NULL) delete[] keyExpansion;
            this->keyExpansion = new uint8_t[(unsigned)a.keyExpLen];
        }
        for(int i = 0; i < a.keyExpLen; i++) this->keyExpansion[i] = a.keyExpansion[i];
    }
    return *this;
}

/*std::ostream& AESencryption::operator << (std::ostream& ost, const Cipher& c) {
    char keyExpansionString[880];
    int rowsAmount = c.keyExpLen >> 5;                                          // -rowsAmount = c.keyExpLen / 32
    int i, j, k, l;
    for(i = 0, j = 0, k = 0; i < rowsAmount; i++, j+=32, k+=64) {               // -Rows with 32 columns
        keyExpansionString[k++] = '\n';
        keyExpansionString[k++] = '\t';
        keyExpansionString[k++] = '\t';
        bytesToHexString(&c.keyExpansion[j], &keyExpansionString[k], 32);       // -Writing 32 bites pointed by &c.keyExpansion[j] in hexadecimal over 65 chars
    }                                                                           //  over &keyExpansionString[k]
    if((l = c.keyExpLen & 31) > 0) {                                            // -l = c.keyExpLen % 31
        keyExpansionString[k++] = '\n';
        keyExpansionString[k++] = '\t';
        keyExpansionString[k++] = '\t';
        bytesToHexString(&c.keyExpansion[j], &keyExpansionString[k], l);
        keyExpansionString[k+(l<<1)] = 0;                                       // -k+(l<<1) = k + l*2
    }
    else keyExpansionString[k] = 0;
    ost << "AES::Cipher object information:\n";
    ost << c.key;
    ost << "\tNr: " << c.Nr << " rounds" << '\n';
    ost << "\tKey Expansion size: " << c.keyExpLen << " bytes" << '\n';
    ost << "\tKey Expansion: " << keyExpansionString << '\n';
    return ost;
}*/

void Cipher::buildKeyExpansion() {
    KeyExpansion* ke_p = KeyExpansionBuildNew(this->key.data, this->Nk, false);
    if(this->keyExpansion == NULL) this->keyExpansion = new uint8_t[this->keyExpLen];
    KeyExpansionWriteBytes(ke_p, this->keyExpansion);
    KeyExpansionDelete(&ke_p);
}

void Cipher::formInitialVector(){                                               // -Simple method for setting the initial vector.
    setInitialVector(this->key.IV.data);
    this->key.initializedIV = true;
}

void Cipher::encrypt(const uint8_t*const data, size_t size, uint8_t*const output) const{
    if(size == 0 || data == NULL) return;
    Key::OpMode opMode = this->key.getOpMode();
    switch(opMode) {
        case Key::OpMode::ECB:
            encryptECB(data, size, this->keyExpansion, this->Nk, output);
            break;
        case Key::OpMode::CBC:
            encryptCBC(data, size, this->keyExpansion, this->Nk, this->key.IV.data, output);
            break;
    }
}

void Cipher::decrypt(const uint8_t*const data, size_t size, uint8_t*const output) const{
    if(size == 0 || data == NULL) return;
    Key::OpMode opMode = this->key.getOpMode();
    switch(opMode) {
        case Key::OpMode::ECB:
            decryptECB(data, size, this->keyExpansion, this->Nk, output);
            break;
        case Key::OpMode::CBC:
            decryptCBC(data, size, this->keyExpansion, this->Nk, this->key.IV.data, output);
            break;
    }
}
