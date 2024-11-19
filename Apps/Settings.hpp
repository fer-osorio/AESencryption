#include"../Source/File.hpp"

#ifndef SETTINGS_HPP
#define SETTINGS_HPP

void setEncryptionObjectFromFile(const char _fileName_[]);
void encryptFile(const char fileName[]);
void decryptFile(const char fileName[]);
void runEncryptionProgram();
void runDecryptionProgram();

#endif