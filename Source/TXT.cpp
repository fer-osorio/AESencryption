#include"TXT.hpp"
#include<fstream>

TXT::TXT(const char* fname) : name(fname) { // -Building from file.
    std::ifstream file;
    file.open(fname);
    if(file.is_open()) {
        file.seekg(0, std::ios::end);
        std::streampos fileSize = file.tellg();
        this->size = fileSize;
        file.seekg(0, std::ios::beg);
        this->content = new char[fileSize];
        file.read(this->content, fileSize);
        file.close();
    } else {
        char errmsg[] = "\nIn TXT.cpp file, TXT::TXT(const char* fname): "
                        "Could not open file ";
        std::cout << errmsg << fname << '\n';
        throw errmsg;
    }
}

TXT::TXT(FileName& fname) : name(fname) {
    std::ifstream file;
    file.open(fname.getNameString());
    if(file.is_open()) {
        file.seekg(0, std::ios::end);
        std::streampos fileSize = file.tellg();
        this->size = fileSize;
        file.seekg(0, std::ios::beg);
        this->content = new char[fileSize];
        file.read(this->content, fileSize);
        file.close();
    } else {
        throw "\nCould not open file...\n";
    }
}

TXT::TXT(const TXT& t) : name(t.name), size(t.size){
    this->content = new char[t.size];
    for(unsigned i = 0; i < t.size; i++) this->content[i] = t.content[i];
}

TXT::~TXT() {
    if(content != NULL) delete[] content;
    content = NULL;
}

void TXT::save(const char* fname) {
    std::ofstream file;
    const char* _fname = NULL;
    if(fname == NULL) {
        _fname = this->name.getNameString();
        file.open(_fname);
    } else {
        file.open(fname);
    }
    if(file.is_open()) {
        file.write(this->content, this->size);
        file.close();
    } else {
        throw "File could not be written.";
    }
}

TXT& TXT::operator = (const TXT& t) {
    if(this != &t) {
        this->~TXT();
        this->name = FileName(t.name);
        this->size = t.size;
        this->content = new char[t.size];
        for(unsigned i = 0; i < t.size; i++) this->content[i] = t.content[i];
    }
    return *this;
}

void encryptCBC(TXT& txt, const AES& e, char IVlocation[16]) {
    FileName keyname = (txt.name.returnThisNewExtension(FileName::key));
    e.encryptCBC(txt.content, txt.size, IVlocation);
    e.saveKey(keyname.getNameString());
    txt.save();
}

void decryptCBC(TXT& txt, const AES& e, const char IV[16]) {
    e.decryptCBC(txt.content, txt.size, IV);
    txt.save();
}
