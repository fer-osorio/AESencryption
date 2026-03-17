#include "../include/file_base_fixture.hpp"
#include "../../third-party/stb/stb_image_write.h"
#include <vector>

FileBaseFixture::FileBaseFixture() { setupTestEnvironment(); }
FileBaseFixture::~FileBaseFixture()  { cleanupTestEnvironment(); }

void FileBaseFixture::setupTestEnvironment() {
    fs::create_directories(testDataDir);
    fs::create_directories(emptyDirPath);
    createValidPng(validPngPath, 10, 10);
}

void FileBaseFixture::cleanupTestEnvironment() {
    if (fs::exists(testDataDir)) {
        for (auto& entry : fs::directory_iterator(testDataDir)) {
            if (entry.path().filename() != ".gitkeep")
                fs::remove_all(entry.path());
        }
    }
}

void FileBaseFixture::createValidPng(const fs::path& path, int width, int height) {
    // Build a known-content RGB image: pixel(x,y) = (x*25, y*25, 128)
    std::vector<uint8_t> pixels(width * height * 3);
    for (int y = 0; y < height; y++)
        for (int x = 0; x < width; x++) {
            int idx = (y * width + x) * 3;
            pixels[idx]     = static_cast<uint8_t>(x * 25);
            pixels[idx + 1] = static_cast<uint8_t>(y * 25);
            pixels[idx + 2] = 128;
        }
    stbi_write_png(path.string().c_str(), width, height, 3, pixels.data(), width * 3);
}
