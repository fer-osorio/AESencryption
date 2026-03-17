#ifndef JPEG_IMAGE_HPP
#define JPEG_IMAGE_HPP

#include "raster_image.hpp"

namespace File {

class JPEG : public RasterImage {
public:
    explicit JPEG(const std::filesystem::path& path, int quality = 90);
    void save(const std::filesystem::path& output_path = "") const override;

private:
    int quality_;
};

} // namespace File

#endif // JPEG_IMAGE_HPP
