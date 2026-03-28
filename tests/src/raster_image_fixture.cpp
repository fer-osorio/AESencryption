#include "../include/raster_image_fixture.hpp"
#include "../../third-party/stb/stb_image_write.h"
#include <fstream>
#include <vector>

void RasterImageFixture::SetUp()    { setupTestEnvironment(); }
void RasterImageFixture::TearDown() { cleanupTestEnvironment(); }

void RasterImageFixture::setupTestEnvironment() {
    fs::create_directories(testDataDir);
    createValidPng(validPngPath, 10, 10);
    createValidPng(smallPngPath, 2, 2);
    createValidPng(largePngPath, 100, 100);
    createCorruptFile(corruptPath);
    createEmptyFile(emptyPath);
    createValidJpeg(validJpegPath, 10, 10);
}

void RasterImageFixture::cleanupTestEnvironment() {
    if (fs::exists(testDataDir))
        fs::remove_all(testDataDir);
}

void RasterImageFixture::createValidPng(const fs::path& path, int width, int height) {
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

void RasterImageFixture::createValidBmp(const fs::path& path, int width, int height) {
    std::vector<uint8_t> pixels(width * height * 3);
    for (int y = 0; y < height; y++)
        for (int x = 0; x < width; x++) {
            int idx = (y * width + x) * 3;
            pixels[idx]     = static_cast<uint8_t>(x * 25);
            pixels[idx + 1] = static_cast<uint8_t>(y * 25);
            pixels[idx + 2] = 128;
        }
    stbi_write_bmp(path.string().c_str(), width, height, 3, pixels.data());
}

void RasterImageFixture::createValidJpeg(const fs::path& path, int width, int height, int quality) {
    std::vector<uint8_t> pixels(width * height * 3);
    for (int y = 0; y < height; y++)
        for (int x = 0; x < width; x++) {
            int idx = (y * width + x) * 3;
            pixels[idx]     = static_cast<uint8_t>(x * 25);
            pixels[idx + 1] = static_cast<uint8_t>(y * 25);
            pixels[idx + 2] = 128;
        }
    stbi_write_jpg(path.string().c_str(), width, height, 3, pixels.data(), quality);
}

void RasterImageFixture::createCorruptFile(const fs::path& path) {
    std::ofstream f(path, std::ios::binary);
    uint8_t garbage[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33 };
    f.write(reinterpret_cast<char*>(garbage), sizeof(garbage));
}

void RasterImageFixture::createEmptyFile(const fs::path& path) {
    std::ofstream f(path, std::ios::binary);
}
