// file_base.cpp
#include"../include/file_base.hpp"
#include"../../include/cipher.hpp" // Include the full definition here
#include<fstream>
#include<cmath>

// Constructor implementation
FileBase::FileBase(const std::filesystem::path& path) : file_path(path) {}

bool FileBase::load() {
    std::ifstream file(this->file_path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        // In a real application, you might throw an exception or log an error.
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

void FileBase::apply_encryption(const Encryptor& c){
    c.encryption(this->data);
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
