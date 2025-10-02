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
        file.read(this->fh.bm, 2);
        if(this->fh.bm[0] == 'B' && this->fh.bm[1] == 'M') {
            // -File Header.
            file.read(reinterpret_cast<char*>(&this->fh.size), 4);
            file.read(reinterpret_cast<char*>(&this->fh.reserved1), 2);
            file.read(reinterpret_cast<char*>(&this->fh.reserved2), 2);
            file.read(reinterpret_cast<char*>(&this->fh.offset), 4);

            // -Image Header.
            file.read(reinterpret_cast<char*>(&this->ih.size), 4);
            file.read(reinterpret_cast<char*>(&this->ih.Width), 4);
            file.read(reinterpret_cast<char*>(&this->ih.Height), 4);
            file.read(reinterpret_cast<char*>(&this->ih.Planes), 2);
            file.read(reinterpret_cast<char*>(&this->ih.BitsPerPixel), 2);
            file.read(reinterpret_cast<char*>(&this->ih.Compression), 4);
            file.read(reinterpret_cast<char*>(&this->ih.SizeOfBitmap), 4);
            file.read(reinterpret_cast<char*>(&this->ih.HorzResolution), 4);
            file.read(reinterpret_cast<char*>(&this->ih.VertResolution), 4);
            file.read(reinterpret_cast<char*>(&this->ih.ColorsUsed), 4);
            file.read(reinterpret_cast<char*>(&this->ih.ColorsImportant), 4);
            this->pixelAmount = static_cast<size_t>(this->ih.Height) * static_cast<size_t>(this->ih.Width);
            this->bytesPerPixel = this->ih.BitsPerPixel / 8;
            this->widthInBytes = this->ih.Width*this->bytesPerPixel;
            file.close();
        } else {
            file.close();
            throw std::runtime_error("Not a valid bitmap file.");
        }
    } else {
        throw std::runtime_error("File could not be opened.");
    }
}

bool Bitmap::load(){
    std::ifstream file;
    file.open(this->file_path, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }
    file.seekg(this->fh.offset);
    this->data.resize(ih.SizeOfBitmap);
    if(file.read(reinterpret_cast<char*>(this->data.data()), ih.SizeOfBitmap)){ // -Initializing bitmap data
        return true;
    }
    this->data.clear();                                                         // Clear data on failure
    return false;
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

bool Bitmap::save(const std::filesystem::path& output_path) const{
    std::ofstream file;
    file.open(output_path, std::ios::binary);
    if(file.is_open()) {
        if(this->fh.bm[0] == 'B' && this->fh.bm[1] == 'M') {
            const uint32_t updatedOffset = sizeof(FileHeader) + sizeof(ImageHeader);
            const uint32_t updatedFileSize = this->ih.SizeOfBitmap + updatedOffset;
            file.write(this->fh.bm, 2);                                         // -File Header.
            file.write(reinterpret_cast<const char*>(&updatedFileSize), 4);                             // ...
            file.write(reinterpret_cast<const char*>(&this->fh.reserved1), 2);                                // ...
            file.write(reinterpret_cast<const char*>(&this->fh.reserved2), 2);                                // ...
            file.write(reinterpret_cast<const char*>(&updatedOffset), 4);                               // ...

            file.write(reinterpret_cast<const char*>(&this->ih.size), 4);                                     // -Image Header.
            file.write(reinterpret_cast<const char*>(&this->ih.Width), 4);                                    // ...
            file.write(reinterpret_cast<const char*>(&this->ih.Height), 4);                                   // ...
            file.write(reinterpret_cast<const char*>(&this->ih.Planes), 2);                                   // ...
            file.write(reinterpret_cast<const char*>(&this->ih.BitsPerPixel), 2);                             // ...
            file.write(reinterpret_cast<const char*>(&this->ih.Compression), 4);                              // ...
            file.write(reinterpret_cast<const char*>(&this->ih.SizeOfBitmap), 4);                             // ...
            file.write(reinterpret_cast<const char*>(&this->ih.HorzResolution), 4);                           // ...
            file.write(reinterpret_cast<const char*>(&this->ih.VertResolution), 4);                           // ...
            file.write(reinterpret_cast<const char*>(&this->ih.ColorsUsed), 4);                               // ...
            file.write(reinterpret_cast<const char*>(&this->ih.ColorsImportant), 4);                          // ...
            file.write(reinterpret_cast<const char*>(this->data.data()), ih.SizeOfBitmap);                           // ...
            file.close();
        } else {
            file.close();
            throw std::runtime_error("Not a valid bitmap file.");
        }
    } else {
        throw std::runtime_error("File could not be written.");
    }
    return true;
}

Bitmap& Bitmap::operator = (const Bitmap &bmp) {
    if(this != &bmp) {                                                          // -Guarding against self assignment
        this->fh.bm[0] = bmp.fh.bm[0];                                          // -Copying file header.
        this->fh.bm[1] = bmp.fh.bm[1];                                          // ...
        this->fh.size = bmp.fh.size;                                            // ...
        this->fh.reserved1 = bmp.fh.reserved1;                                  // ...
        this->fh.reserved2 = bmp.fh.reserved2;                                  // ...
        this->fh.offset = bmp.fh.offset;                                        // ...

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

    return this->data == bmp.data;
}

bool Bitmap::operator != (const Bitmap &bmp) const{
    return !this->operator==(bmp);
}

uint8_t Bitmap::getPixelComponentValue(size_t i, size_t j, RGB c)  const{
    size_t h = static_cast<size_t>(this->ih.Height);
    size_t w = static_cast<size_t>(this->ih.Width);
    if(i > h) i %= h;
    if(j > w) j %= w;
    return this->data[i*this->widthInBytes + j*this->bytesPerPixel + static_cast<unsigned>(c)]; // -Just to prevent a compiler warning from appearing
}
