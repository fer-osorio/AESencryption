#include "../include/file_base_fixture.hpp"
#include <fstream>

FileBaseFixture::FileBaseFixture() { setupTestEnvironment(); }
FileBaseFixture::~FileBaseFixture()  { cleanupTestEnvironment(); }

void FileBaseFixture::setupTestEnvironment() {
    fs::create_directories(testDataDir);
    createBinaryFile(validFilePath, FILE_BASE_FIXTURE_FILE_SIZE);
}

void FileBaseFixture::cleanupTestEnvironment() {
    if (fs::exists(testDataDir)) {
        for (auto& entry : fs::directory_iterator(testDataDir)) {
            if (entry.path().filename() != ".gitkeep")
                fs::remove_all(entry.path());
        }
    }
}

void FileBaseFixture::createBinaryFile(const fs::path& path, size_t size) {
    // Write bytes 0x00, 0x01, 0x02, ... (mod 256) — known, deterministic content.
    std::ofstream f(path, std::ios::binary);
    for (size_t i = 0; i < size; i++)
        f.put(static_cast<char>(i & 0xFF));
}
