#include"../include/file_base.hpp"
#include"../../include/encryptor.hpp"
#include"../../metrics-analysis/include/data_randomness.hpp"
#include<fstream>
#include<cmath>

// Constructor implementation
FileBase::FileBase(const std::filesystem::path& path) : file_path(path) {}

bool FileBase::load() {
    std::ifstream file;
    file.open(this->file_path, std::ios::binary | std::ios::ate);
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

bool FileBase::save(const std::filesystem::path& output_path) const{
    std::ofstream file;
    file.open(this->file_path, std::ios::binary);
    if(!file.is_open()) {
        return false;
    }
    if(file.write(reinterpret_cast<const char*>(this->data.data()), this->data.size())){
        file.close();
        return true;
    }
    return false;
}

void FileBase::apply_encryption(const Encryptor& c){
    c.encryption(this->data,this->data);
}

DataRandomness FileBase::calculate_statistics() const{
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
