#ifndef RASTER_IMAGE_FIXTURE_HPP
#define RASTER_IMAGE_FIXTURE_HPP

#include <gtest/gtest.h>
#include <filesystem>

namespace fs = std::filesystem;

class RasterImageFixture : public ::testing::Test {
public:
    static void createValidPng(const fs::path& path, int width, int height);
    static void createValidBmp(const fs::path& path, int width, int height);
    static void createValidJpeg(const fs::path& path, int width, int height, int quality = 90);

protected:
    fs::path testDataDir     = fs::path("tests/data/raster_image");
    fs::path validPngPath    = testDataDir / "valid_10x10.png";
    fs::path smallPngPath    = testDataDir / "small_2x2.png";
    fs::path largePngPath    = testDataDir / "large_100x100.png";
    fs::path corruptPath     = testDataDir / "corrupt.png";
    fs::path emptyPath       = testDataDir / "empty.png";
    fs::path nonexistentPath = testDataDir / "does_not_exist.png";
    fs::path validJpegPath   = testDataDir / "valid_10x10.jpg";

    void SetUp() override;
    void TearDown() override;

private:
    void setupTestEnvironment();
    void cleanupTestEnvironment();
    void createCorruptFile(const fs::path& path);
    void createEmptyFile(const fs::path& path);
};

#endif // RASTER_IMAGE_FIXTURE_HPP
