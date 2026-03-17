#include "../include/bitmap.hpp"
#include "../../third-party/stb/stb_image_write.h"
#include <fstream>
#include <stdexcept>

using namespace File;

const char*const Bitmap::RGBlabels[static_cast<unsigned>(RGB::Color_amount)] = {
    "Red", "Green", "Blue"
};
const char*const Bitmap::DirectionLabels[static_cast<unsigned>(Direction::direction_amount)] = {
    "Horizontal", "Vertical", "Diagonal"
};

Bitmap::Bitmap(const std::filesystem::path& path) : RasterImage(path) {
    std::ifstream probe(path, std::ios::binary);
    if (!probe.is_open()) {
        throw std::runtime_error("File could not be opened.");
    }
}

Bitmap::Bitmap(const Bitmap& bmp) : RasterImage(bmp) {}

void Bitmap::save(const std::filesystem::path& output_path) const {
    if (this->data.empty()) {
        throw std::logic_error(
            "In member function void Bitmap::save(const std::filesystem::path& output_path) const: Trying to save empty bitmap."
        );
    }
    const auto& out = output_path.empty() ? this->file_path : output_path;
    int result = stbi_write_bmp(
        out.string().c_str(),
        width_, height_, channels_,
        this->data.data());
    if (!result) {
        throw std::runtime_error("Bitmap::save(): failed to write file.");
    }
}

Bitmap& Bitmap::operator = (const Bitmap& bmp) {
    if (this != &bmp) {
        RasterImage::operator=(bmp);
    }
    return *this;
}

std::ostream& File::operator << (std::ostream& stream, const Bitmap& bmp) {
    stream << "File path:";
    stream << "\n\t" << bmp.file_path;
    stream << "\nImage info:";
    stream << "\n\twidth: "    << bmp.width_;
    stream << "\n\theight: "   << bmp.height_;
    stream << "\n\tchannels: " << bmp.channels_;
    return stream;
}

bool Bitmap::operator == (const Bitmap& bmp) const {
    return width_    == bmp.width_    &&
           height_   == bmp.height_   &&
           channels_ == bmp.channels_ &&
           this->data == bmp.data;
}

bool Bitmap::operator != (const Bitmap& bmp) const {
    return !this->operator==(bmp);
}

uint8_t Bitmap::getPixelComponentValue(size_t i, size_t j, RGB c) const {
    size_t h = static_cast<size_t>(height_);
    size_t w = static_cast<size_t>(width_);
    if (i > h) i %= h;
    if (j > w) j %= w;
    return this->data[
        i * w * static_cast<size_t>(channels_) +
        j * static_cast<size_t>(channels_) +
        static_cast<unsigned>(c)
    ];
}
