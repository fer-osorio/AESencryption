#include "../include/jpeg_image.hpp"
#include "../../third-party/stb/stb_image_write.h"
#include <stdexcept>

namespace File {

JPEG::JPEG(const std::filesystem::path& path, int quality)
    : RasterImage(path), quality_(quality) {}

void JPEG::save(const std::filesystem::path& output_path) const {
    const auto& out = output_path.empty() ? this->file_path : output_path;
    int result = stbi_write_jpg(
        out.string().c_str(),
        width_, height_, channels_,
        this->data.data(),
        quality_);
    if (!result)
        throw std::runtime_error("JPEG::save(): failed to write file");
}

} // namespace File
