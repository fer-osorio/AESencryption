#ifndef IMAGE_FACTORY_HPP
#define IMAGE_FACTORY_HPP

#include "file_base.hpp"
#include <filesystem>
#include <memory>

namespace File {

/**
 * @brief Creates the appropriate FileBase subclass for a given image path.
 *
 * Dispatch is based solely on the file extension (case-insensitive):
 *   .bmp              → Bitmap
 *   .png              → PNG
 *   .jpg / .jpeg      → JPEG
 *
 * @param path  Path to the image file.
 * @return      Owning pointer to the concrete FileBase subclass.
 * @throws      std::invalid_argument if the extension is not supported.
 *
 * @note Adding a new format requires only a new branch in the
 *       corresponding .cpp — no other files need to change.
 */
std::unique_ptr<FileBase> make_image(const std::filesystem::path& path);

/**
 * @brief Returns true if the extension of 'path' maps to a lossy format.
 *
 * Used by callers that want to warn the user before a destructive
 * encrypt-then-save cycle (e.g. JPEG).
 */
bool image_is_lossy(const std::filesystem::path& path) noexcept;

} // namespace File

#endif // IMAGE_FACTORY_HPP
