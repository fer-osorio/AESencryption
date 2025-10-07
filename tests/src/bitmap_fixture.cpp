#include "../include/bitmap_fixture.hpp"
#include <fstream>

BitmapTestFixture::BitmapTestFixture() {
    setupTestEnvironment();
}

BitmapTestFixture::~BitmapTestFixture() {
    cleanupTestEnvironment();
}

void BitmapTestFixture::setupTestEnvironment() {
    // Create test data directory
    if (!fs::exists(testDataDir)) {
        fs::create_directory(testDataDir);
    }
    // Create test BMP files
    createValidBitmap(validBmpPath, 10, 10);
    createValidBitmap(smallBmpPath, 2, 2);
    createValidBitmap(largeBmpPath, 100, 100);
    createCorruptBitmap(corruptHeaderPath);
    createWrongMagicBitmap(wrongMagicPath);
}

void BitmapTestFixture::cleanupTestEnvironment() {
    // Clean up test files
    if (fs::exists(testDataDir)) {
        for (auto& entry : fs::directory_iterator(testDataDir)) {
            if (entry.path().filename() != ".gitkeep") {    // Avoid delete directories tracked by git
                fs::remove(entry.path());
            }
        }
    }
}

void BitmapTestFixture::createValidBitmap(const fs::path& path, int width, int height) {
    std::ofstream file(path, std::ios::binary);
    if (!file) return;

    // Calculate sizes
    int rowSize = ((width * 3 + 3) / 4) * 4; // Row size must be multiple of 4
    int imageSize = rowSize * height;
    int fileSize = 54 + imageSize; // 14 (file header) + 40 (info header) + image data

    // BMP File Header (14 bytes)
    file.put('B');
    file.put('M');
    writeInt32(file, fileSize);
    writeInt16(file, 0); // reserved1
    writeInt16(file, 0); // reserved2
    writeInt32(file, 54); // offset to pixel data

    // DIB Header (BITMAPINFOHEADER - 40 bytes)
    writeInt32(file, 40); // header size
    writeInt32(file, width);
    writeInt32(file, height);
    writeInt16(file, 1); // color planes
    writeInt16(file, 24); // bits per pixel
    writeInt32(file, 0); // no compression
    writeInt32(file, imageSize);
    writeInt32(file, 2835); // horizontal resolution (72 DPI)
    writeInt32(file, 2835); // vertical resolution (72 DPI)
    writeInt32(file, 0); // colors in palette
    writeInt32(file, 0); // important colors

    // Pixel data (BGR format with padding)
    for (int y = 0; y < height; y++) {
        for (int x = 0; x < width; x++) {
            file.put(static_cast<uint8_t>(x * 255 / width)); // Blue
            file.put(static_cast<uint8_t>(y * 255 / height)); // Green
            file.put(static_cast<uint8_t>(128)); // Red (constant)
        }
        // Add padding to make row size multiple of 4
        for (int p = 0; p < (rowSize - width * 3); p++) {
            file.put(0);
        }
    }

    file.close();
}

// Creates a BMP with corrupt header
void BitmapTestFixture::createCorruptBitmap(const fs::path& path) {
    std::ofstream file(path, std::ios::binary);
    file.put('B');
    file.put('M');
    // Write garbage data
    for (int i = 0; i < 51; i++) {
        file.put(static_cast<char>(i % 256));
    }
    file.close();
}

// Creates a file with wrong magic bytes
void BitmapTestFixture::createWrongMagicBitmap(const fs::path& path) {
    std::ofstream file(path, std::ios::binary);
    file.put('P'); // Wrong magic
    file.put('N'); // Wrong magic
    for (int i = 0; i < 100; i++) {
        file.put(0);
    }
    file.close();
}

// Helper functions to write binary data
void BitmapTestFixture::writeInt16(std::ofstream& file, int16_t value) {
    file.write(reinterpret_cast<const char*>(&value), sizeof(value));
}

void BitmapTestFixture::writeInt32(std::ofstream& file, int32_t value) {
    file.write(reinterpret_cast<const char*>(&value), sizeof(value));
}
