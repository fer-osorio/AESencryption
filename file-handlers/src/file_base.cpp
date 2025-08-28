// file_base.cpp
#include "../include/file_base.hpp"
//#include "encryptor.hpp" // Include the full definition here
#include <fstream>
#include <cmath>

// Constructor implementation
FileBase::FileBase(const std::filesystem::path& path) : file_path(path) {}

bool FileBase::load() {
    std::ifstream file(file_path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        // In a real application, you might throw an exception or log an error.
        return false;
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    data.resize(size);
    if (file.read(reinterpret_cast<char*>(data.data()), size)) {
        return true;
    }

    data.clear(); // Clear data on failure
    return false;
}

// ... other method implementations ...
