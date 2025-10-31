#include"../include/file_base.hpp"
#include"../../include/encryptor.hpp"
#include"../../metrics-analysis/include/data_randomness.hpp"
#include<fstream>
#include<cmath>

using namespace File;

// Constructor implementation
FileBase::FileBase(const std::filesystem::path& path) : file_path(path) {}

void FileBase::load() {
    std::ifstream file;
    file.open(this->file_path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        throw std::runtime_error(
            "In member function void FileBase::load(): Could not open file."
        );
    }
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    this->data.resize(size);
    if (!file.read(reinterpret_cast<char*>(this->data.data()), size)) {
        this->data.clear(); // Clear data on failure
        throw std::runtime_error(
            "In member function void FileBase::load(): Could not read file."
        );
    }
}

void FileBase::save(const std::filesystem::path& output_path) const{
    std::ofstream file;
    file.open(this->file_path, std::ios::binary);
    if(!file.is_open()) {
        throw std::runtime_error(
            "In member function bool FileBase::save(const std::filesystem::path& output_path) const: Could not open file."
        );
    }
    if(!file.write(reinterpret_cast<const char*>(this->data.data()), this->data.size())){
        throw std::runtime_error(
            "In member function bool FileBase::save(const std::filesystem::path& output_path) const: Could not write file."
        );
    }
}

void FileBase::apply_encryption(const Encryptor& algorithm){
    try{
        algorithm.encryption(this->data,this->data);
    } catch(...){
        throw;
    }
}

void FileBase::apply_decryption(const Encryptor& algorithm){
    try{
        algorithm.decryption(this->data,this->data);
    } catch(...){
        throw;
    }
}

DataRandomness FileBase::calculate_randomness() const{
    return DataRandomness(reinterpret_cast<const std::vector<std::byte>&>(this->data));
}

const std::filesystem::path& FileBase::get_path() const{
    return this->file_path;
}
const std::vector<uint8_t>& FileBase::get_data() const{
    return this->data;
}
size_t FileBase::get_size() const{
    return this->data.size();
}
