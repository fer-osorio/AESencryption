#include"../include/textf.hpp"
#include<fstream>
#include<cstring>

using namespace File;

TXT::TXT(const std::filesystem::path& path) : FileBase(path) {}

void TXT::load(){
    std::ifstream file;
    file.open(this->file_path, std::ios::ate);
    if (!file.is_open()) {
        throw std::runtime_error(
            "In member function void TXT::load(): Could not open file."
        );
    }
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    this->data.resize(size);
    if (!file.read(reinterpret_cast<char*>(this->data.data()), size)) {
        this->data.clear(); // Clear data on failure
        throw std::runtime_error(
            "In member function void TXT::load(): Could not read file."
        );
    }
}

void TXT::save(const std::filesystem::path& output_path) const{
    std::ofstream file;
    file.open(this->file_path);
    if(!file.is_open()) {
        throw std::runtime_error(
            "In member function void TXT::save(const std::filesystem::path& output_path) const: Could not open file."
        );
    }
    if(!file.write(reinterpret_cast<const char*>(this->data.data()), this->data.size())){
        throw std::runtime_error(
            "In member function void TXT::save(const std::filesystem::path& output_path) const: Could not write file."
        );
    }
}
