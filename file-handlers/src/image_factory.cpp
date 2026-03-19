#include "../include/image_factory.hpp"
#include "../include/bitmap.hpp"
#include "../include/png_image.hpp"
#include "../include/jpeg_image.hpp"

#include <algorithm>
#include <stdexcept>

namespace File {

// ---------------------------------------------------------------------------
// Internal helper
// ---------------------------------------------------------------------------

static std::string lower_extension(const std::filesystem::path& path) {
    std::string ext = path.extension().string();
    std::transform(
        ext.begin(), ext.end(), ext.begin(),
       [](unsigned char c){ return static_cast<char>(std::tolower(c)); }
    );
    return ext;
}

// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

std::unique_ptr<FileBase> make_image(const std::filesystem::path& path) {
    const std::string ext = lower_extension(path);

    if (ext == ".bmp")
        return std::make_unique<Bitmap>(path);

    if (ext == ".png")
        return std::make_unique<PNG>(path);

    if (ext == ".jpg" || ext == ".jpeg")
        return std::make_unique<JPEG>(path);

    throw std::invalid_argument(
        "Unsupported image format: '" + ext + "'. "
        "Supported extensions: .bmp, .png, .jpg, .jpeg"
    );
}

bool image_is_lossy(const std::filesystem::path& path) noexcept {
    const std::string ext = lower_extension(path);
    return (ext == ".jpg" || ext == ".jpeg");
}

} // namespace File
