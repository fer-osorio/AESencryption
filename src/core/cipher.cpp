#include"../../include/cipher.hpp"
#include"../data-encryption/AES/AES.h"
#include"../data-encryption/operation_modes/operation_modes.h"
#include"../utils/print_bytes/print_bytes.hpp"

using namespace AESencryption;

static size_t getNkfromLenbit(Key::LenBits lb){
    return size_t(lb)/32;
}
static size_t getNrFromNk(size_t Nk){
    return Nk+6;
}
static size_t getKeyExpansionByteLenFromNr(size_t Nr){
    return (Nr+1)*Nb*4;
}

Cipher::Cipher() {
    this->keyExpansion = new uint8_t[this->keyExpansionLength];
    for(int i = 0; i < this->keyExpansionLength; i++) this->keyExpansion[i] = 0;         // -Since the key constitutes of just zeros, key expansion is also just zeros
}

Cipher::Cipher(const Key& k)
    :key(k), Nk(getNkfromLenbit(k.lenBits)), Nr(getNrFromNk(Nk)), keyExpansionLength(getKeyExpansionByteLenFromNr(Nr)) {
    this->buildKeyExpansion();
}

Cipher::Cipher(const Cipher& a)
    : key(a.key), Nk(a.Nk), Nr(a.Nr), keyExpansionLength(a.keyExpansionLength) {
    this->keyExpansion = new uint8_t[(unsigned)a.keyExpansionLength];
    for(int i = 0; i < a.keyExpansionLength; i++) this->keyExpansion[i] = a.keyExpansion[i];
}

Cipher::~Cipher() {
    if(keyExpansion != NULL) delete[] keyExpansion;
    keyExpansion = NULL;
}

Cipher& Cipher::operator = (const Cipher& a) {
    if(this != &a) {
        this->key = a.key;
        if(this->keyExpansionLength != a.keyExpansionLength) {
            this->Nk = a.Nk;
            this->Nr = a.Nr;
            this->keyExpansionLength = a.keyExpansionLength;
            if(this->keyExpansion != NULL) delete[] keyExpansion;
            this->keyExpansion = new uint8_t[(unsigned)a.keyExpansionLength];
        }
        for(int i = 0; i < a.keyExpansionLength; i++) this->keyExpansion[i] = a.keyExpansion[i];
    }
    return *this;
}

std::ostream& AESencryption::operator<<(std::ostream& ost, const Cipher& c) {
    ost << "AES::Cipher object information:\n";
    ost << c.key;
    ost << "\tNr: " << c.Nr << " rounds\n";
    ost << "\tKey Expansion size: " << c.keyExpansionLength << " bytes\n";
    ost << "\tKey Expansion:";

    const size_t bytes_per_row = 32;
    size_t bytes_to_print;
    if (c.keyExpansion) {
        for(size_t i = 0; i < c.keyExpansionLength; i += bytes_per_row) {
            ost << "\n\t\t"; // Start each new line of the expansion
            // Determine how many bytes to print in this row (handles the last partial row). Here, we are supposing KeyLenExp is a multiple of 32,
            // which is true for AES standard.
            bytes_to_print = (i + bytes_per_row > c.keyExpansionLength) ? (c.keyExpansionLength - i) : bytes_per_row;
            print_bytes_as_hex(ost, &c.keyExpansion[i], bytes_to_print);
        }
    } else {
        ost << " (null)";
    }
    ost << '\n';
    return ost;
}

void Cipher::buildKeyExpansion() {
    KeyExpansion* ke_p = KeyExpansionBuildNew(this->key.data, this->Nk, false);
    if(this->keyExpansion == NULL) this->keyExpansion = new uint8_t[this->keyExpansionLength];
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
