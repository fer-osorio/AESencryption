#include "../include/png_image.hpp"
#include "../../third-party/stb/stb_image_write.h"
#include <stdexcept>

namespace File {

PNG::PNG(const std::filesystem::path& path)
    : RasterImage(path) {}

void PNG::save(const std::filesystem::path& output_path) const {
    const auto& out = output_path.empty() ? this->file_path : output_path;
    int result = stbi_write_png(
        out.string().c_str(),
        width_, height_, channels_,
        this->data.data(),
        width_ * channels_);
    if (!result)
        throw std::runtime_error("PNG::save(): failed to write file");
}

} // namespace File
