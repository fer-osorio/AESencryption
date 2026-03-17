#ifndef RASTER_IMAGE_HPP
#define RASTER_IMAGE_HPP

#include "file_base.hpp"

namespace File {

class RasterImage : public FileBase {
public:
    explicit RasterImage(const std::filesystem::path& path);
    void load() override;  // stbi_load → this->data; frees stb buffer immediately

protected:
    int width_    = 0;
    int height_   = 0;
    int channels_ = 0;
};

} // namespace File

#endif // RASTER_IMAGE_HPP
