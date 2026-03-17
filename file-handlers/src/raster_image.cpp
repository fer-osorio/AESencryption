#include "../include/raster_image.hpp"
#include "../../third-party/stb/stb_image.h"
#include <stdexcept>
#include <string>

namespace File {

RasterImage::RasterImage(const std::filesystem::path& path)
    : FileBase(path) {}

void RasterImage::load() {
    if (!this->data.empty()) return;
    int w, h, ch;
    uint8_t* pixels = stbi_load(
        this->file_path.string().c_str(), &w, &h, &ch, 0);
    if (!pixels)
        throw std::runtime_error(
            std::string("RasterImage::load(): ") + stbi_failure_reason());
    width_    = w;
    height_   = h;
    channels_ = ch;
    this->data.assign(pixels, pixels + w * h * ch);
    stbi_image_free(pixels);
}

} // namespace File
