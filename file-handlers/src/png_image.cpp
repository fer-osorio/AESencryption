#include "../include/png_image.hpp"
#include "../../third-party/stb/stb_image_write.h"
#include <stdexcept>

namespace File {

PNG::PNG(const std::filesystem::path& path)
    : RasterImage(path) {}

void PNG::save(const std::filesystem::path& output_path) const {
    if (this->data.empty()) {
        throw std::logic_error(
            "In member function "
            "void PNG::save(const std::filesystem::path& output_path) const"
            ": Trying to save empty png."
        );
    }
    const auto& out = output_path.empty() ? this->file_path : output_path;
    const std::string ext = out.extension().string();
    int result;
    if (ext == ".jpg" || ext == ".jpeg") {
        result = stbi_write_jpg(
            out.string().c_str(),
            width_, height_, channels_,
            this->data.data(),
            90);
        if (!result)
            throw std::runtime_error("PNG::save(): failed to write JPEG file");
    } else {
        result = stbi_write_png(
            out.string().c_str(),
            width_, height_, channels_,
            this->data.data(),
            width_ * channels_);
        if (!result)
            throw std::runtime_error("PNG::save(): failed to write file");
    }
}

} // namespace File
