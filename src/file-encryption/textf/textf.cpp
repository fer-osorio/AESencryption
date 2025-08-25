#include"textf.hpp"
#include<fstream>
#include<cstring>

TXT::TXT(const char* fname) { // -Building from file.
    std::ifstream file;
    file.open(fname);
    if(file.is_open()) {
        this->name = new char[strlen(fname)];
        strcpy(this->name, fname);
        file.seekg(0, std::ios::end);
        std::streampos fileSize = file.tellg();
        this->size = fileSize;
        file.seekg(0, std::ios::beg);
        this->content = new char[fileSize];
        file.read(this->content, fileSize);
        file.close();
    } else {
        cerrMessageBeforeThrow("TXT::TXT(const char* fname)", "Could not open file.");
        throw std::runtime_error("Could not open file.");
    }
}

TXT::TXT(const TXT& t): size(t.size) {
    this->name = new char[strlen(t.name)];
    strcpy(this->name, t.name);
    this->content = new char[t.size];
    for(unsigned i = 0; i < t.size; i++) this->content[i] = t.content[i];
}

void TXT::save(const char* fname)  const{                                       // -The user can provide a name for the file
    std::ofstream file;
    if(fname != NULL)
        file.open(fname);
    else                                                                        // -If no name provided, the string inside attribute name will be used
        file.open(this->name);
    if(file.is_open()) {
        file.write(this->content, this->size);
        file.close();
    } else {
        cerrMessageBeforeThrow("void TXT::save(const char* fname)", "File could not be written.");
        throw std::runtime_error("File could not be written.");
    }
}

TXT& TXT::operator = (const TXT& t) {
    if(this != &t) {
        if(this->name != NULL) delete[] this->name;
        this->name = new char[strlen(t.name)];
        strcpy(this->name, t.name);
        this->size = t.size;
        if(content != NULL) delete[] content;
        this->content = new char[t.size];
        for(unsigned i = 0; i < t.size; i++) this->content[i] = t.content[i];
    }
    return *this;
}
