#ifndef PNG_IMAGE_HPP
#define PNG_IMAGE_HPP

#include "raster_image.hpp"

namespace File {

class PNG : public RasterImage {
public:
    explicit PNG(const std::filesystem::path& path);
    void save(const std::filesystem::path& output_path = "") const override;
};

} // namespace File

#endif // PNG_IMAGE_HPP
