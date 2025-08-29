#include"../include/textf.hpp"
#include<fstream>
#include<cstring>

TXT::TXT(const std::filesystem::path& path) : FileBase(path) {}

bool TXT::load(){
    std::ifstream file;
    file.open(this->file_path, std::ios::ate);
    if (!file.is_open()) {
        return false;
    }
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    this->data.resize(size);
    if (file.read(reinterpret_cast<char*>(this->data.data()), size)) {
        return true;
    }
    this->data.clear(); // Clear data on failure
    return false;
}

bool TXT::save(const std::filesystem::path& output_path) const{
    std::ofstream file;
    file.open(this->file_path);
    if(!file.is_open()) {
        return false;
    }
    if(file.write(reinterpret_cast<const char*>(this->data.data()), this->data.size())){
        file.close();
        return true;
    }
    return false;
}
