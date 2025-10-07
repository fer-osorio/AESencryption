#include"../include/bitmap.hpp"
#include<fstream>
#include<cstring>
#include<cmath>
#include<exception>

using namespace File;

const char*const Bitmap::RGBlabels[static_cast<unsigned>(RGB::Color_amount)] = {
    "Red", "Green", "Blue"
};
const char*const Bitmap::DirectionLabels[static_cast<unsigned>(Direction::direction_amount)] = {
    "Horizontal", "Vertical", "Diagonal"
};

Bitmap::Bitmap(const std::filesystem::path& path) : FileBase(path){
    std::ifstream file;
    file.open(path, std::ios::binary);
    int i, j, sz = 0;
    if(file.is_open()) {
        // -File Header.
        if(!file.read(reinterpret_cast<char*>(&this->fh), sizeof(FileHeader) ) ){
            file.close();
            throw std::runtime_error("Could not read file header.");
        }
        if(this->fh.bm[0] != 'B' || this->fh.bm[1] != 'M') {
            file.close();
            throw std::runtime_error("Not a valid bitmap file.");
        }
        // -Image Header.
        if(!file.read(reinterpret_cast<char*>(&this->ih), sizeof(ImageHeader) ) ){
            file.close();
            throw std::runtime_error("Could not read image header.");
        }
        this->pixelAmount = static_cast<size_t>(this->ih.Height) * static_cast<size_t>(this->ih.Width);
        this->bytesPerPixel = this->ih.BitsPerPixel / 8;
        this->widthInBytes = this->ih.Width*this->bytesPerPixel;
        file.close();
    } else {
        throw std::runtime_error("File could not be opened.");
    }
}

void Bitmap::load(){
    std::ifstream file;
    if(!this->data.empty()) return;                                             // Guarding against double load.
    file.open(this->file_path, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error(
            "In member function void Bitmap::load(): Could not open file."
        );
    }
    file.seekg(this->fh.offset);
    this->data.resize(ih.SizeOfBitmap);
    if(!file.read(reinterpret_cast<char*>(this->data.data()), ih.SizeOfBitmap)){ // -Initializing bitmap data
        this->data.clear();                                                      // Clear data on failure
        throw std::runtime_error(
            "In member function void Bitmap::load(): Could not open file."
        );
    }
}

Bitmap::Bitmap(const Bitmap& bmp) : FileBase(bmp){
    this->fh.bm[0] = bmp.fh.bm[0];                                              // -Initializing file header.
    this->fh.bm[1] = bmp.fh.bm[1];                                              // ...
    this->fh.size = bmp.fh.size;                                                // ...
    this->fh.reserved1 = bmp.fh.reserved1;                                      // ...
    this->fh.reserved2 = bmp.fh.reserved2;                                      // ...
    this->fh.offset = bmp.fh.offset;                                            // ...

    this->ih = bmp.ih;                                                          // -Initializing image header. Using the default member to member copy.

    this->pixelAmount = bmp.pixelAmount;
    this->bytesPerPixel = bmp.bytesPerPixel;
    this->widthInBytes = bmp.widthInBytes;

    this->data = bmp.data;
}

void Bitmap::save(const std::filesystem::path& output_path) const{
    std::ofstream file;
    if (this->data.empty()) {
        throw std::logic_error(
            "In member function void Bitmap::save(const std::filesystem::path& output_path) const: Trying to save empty bitmap."
        );
    }
    file.open(output_path, std::ios::binary);
    if(file.is_open()) {
        if(this->fh.bm[0] == 'B' && this->fh.bm[1] == 'M') {
            const uint32_t updatedOffset = sizeof(FileHeader) + sizeof(ImageHeader);
            const uint32_t updatedFileSize = this->ih.SizeOfBitmap + updatedOffset;
            file.write(this->fh.bm, 2);                                         // -File Header.
            file.write(reinterpret_cast<const char*>(&updatedFileSize), 4);     // ...
            file.write(reinterpret_cast<const char*>(&this->fh.reserved1), 2);  // ...
            file.write(reinterpret_cast<const char*>(&this->fh.reserved2), 2);  // ...
            file.write(reinterpret_cast<const char*>(&updatedOffset), 4);       // ...

            file.write(reinterpret_cast<const char*>(&this->ih.size), 4);       // -Image Header.
            file.write(reinterpret_cast<const char*>(&this->ih.Width), 4);      // ...
            file.write(reinterpret_cast<const char*>(&this->ih.Height), 4);     // ...
            file.write(reinterpret_cast<const char*>(&this->ih.Planes), 2);     // ...
            file.write(reinterpret_cast<const char*>(&this->ih.BitsPerPixel), 2);   // ...
            file.write(reinterpret_cast<const char*>(&this->ih.Compression), 4);    // ...
            file.write(reinterpret_cast<const char*>(&this->ih.SizeOfBitmap), 4);   // ...
            file.write(reinterpret_cast<const char*>(&this->ih.HorzResolution), 4); // ...
            file.write(reinterpret_cast<const char*>(&this->ih.VertResolution), 4); // ...
            file.write(reinterpret_cast<const char*>(&this->ih.ColorsUsed), 4);     // ...
            file.write(reinterpret_cast<const char*>(&this->ih.ColorsImportant), 4);// ...
            file.write(reinterpret_cast<const char*>(this->data.data()), ih.SizeOfBitmap);  // ...
            file.close();
        } else {
            file.close();
            throw std::runtime_error("Not a valid bitmap file.");
        }
    } else {
        throw std::runtime_error("File could not be written.");
    }
}

Bitmap& Bitmap::operator = (const Bitmap &bmp) {
    if(this != &bmp) {                                                          // -Guarding against self assignment
        FileBase::operator=(bmp);
        memcpy(&this->fh, &bmp.fh, sizeof(FileHeader) );                        // -Copying file header.
        this->ih = bmp.ih;                                                      // -Copying image header. Using the default member to member copy.
        this->pixelAmount = bmp.pixelAmount;
        this->bytesPerPixel = bmp.bytesPerPixel;
        this->widthInBytes = bmp.widthInBytes;
    }
    return *this;
}

std::ostream& File::operator << (std::ostream &stream, const Bitmap &bmp) {
    stream << "File path:";
    stream << "\n\t" << bmp.file_path;
    stream << "\nFile Header: ";
    stream << "\n\tbm: " << bmp.fh.bm[0] << bmp.fh.bm[1];
    stream << "\n\tsize: " << bmp.fh.size;
    stream << "\n\treserved1: " << bmp.fh.reserved1;
    stream << "\n\treserved2: " << bmp.fh.reserved2;
    stream << "\n\toffset: " << bmp.fh.offset;

    stream << "\nImage Header: ";
    stream << "\n\tsize: " << bmp.ih.size;
    stream << "\n\twidth: " << bmp.ih.Width;
    stream << "\n\theight: " << bmp.ih.Height;
    stream << "\n\tplanes: " << bmp.ih.Planes;
    stream << "\n\tbits per pixel: " << bmp.ih.BitsPerPixel;
    stream << "\n\tcompression: " << bmp.ih.Compression;
    stream << "\n\timage size: " << bmp.ih.SizeOfBitmap;
    stream << "\n\thorizontal resolution: " << bmp.ih.HorzResolution;
    stream << "\n\tvertical resolution: " << bmp.ih.VertResolution;
    stream << "\n\tcolors used: " << bmp.ih.ColorsUsed;
    stream << "\n\tcolors important: " << bmp.ih.ColorsImportant;

    return stream;
}

bool Bitmap::operator == (const Bitmap &bmp) const{
    bool equal =
    this->fh.bm[0] == bmp.fh.bm[0] &&
    this->fh.bm[1] == bmp.fh.bm[1] &&
    this->fh.size  == bmp.fh.size  &&
    this->fh.reserved1 == bmp.fh.reserved1 &&
    this->fh.reserved2 == bmp.fh.reserved2 &&
    this->fh.offset    == bmp.fh.offset    &&
    this->ih.size      == bmp.ih.size      &&
    this->ih.Height    == bmp.ih.Height    &&
    this->ih.Width     == bmp.ih.Width     &&
    this->ih.Planes    == bmp.ih.Planes    &&
    this->ih.BitsPerPixel   == bmp.ih.BitsPerPixel &&
    this->ih.Compression    == bmp.ih.Compression  &&
    this->ih.SizeOfBitmap   == bmp.ih.SizeOfBitmap &&
    this->ih.HorzResolution == bmp.ih.HorzResolution &&
    this->ih.VertResolution == bmp.ih.VertResolution &&
    this->ih.ColorsUsed     == bmp.ih.ColorsUsed     &&
    this->ih.ColorsImportant== bmp.ih.ColorsImportant;

    if(!equal) return false;
    return equal && this->data == bmp.data;
}

bool Bitmap::operator != (const Bitmap &bmp) const{
    return !this->operator==(bmp);
}

uint8_t Bitmap::getPixelComponentValue(size_t i, size_t j, RGB c)  const{
    size_t h = static_cast<size_t>(this->ih.Height);
    size_t w = static_cast<size_t>(this->ih.Width);
    if(i > h) i %= h;
    if(j > w) j %= w;
    return this->data[
        i*this->widthInBytes + j*this->bytesPerPixel + static_cast<unsigned>(c)
    ];
}

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
            if (entry.path().filename() != ".gitkeep") {
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
