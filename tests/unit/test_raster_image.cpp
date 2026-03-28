// Unit test suite for RasterImage contracts, exercised via File::PNG and File::JPEG
#include <gtest/gtest.h>
#include "../../file-handlers/include/png_image.hpp"
#include "../../file-handlers/include/jpeg_image.hpp"
#include "../include/raster_image_fixture.hpp"
#include "../../core-crypto/include/encryptor.hpp"
#include <filesystem>

namespace fs = std::filesystem;

// Minimal mock: XOR every byte with 0xAB — self-inverse
class XorEncryptor : public Encryptor {
public:
    void encryption(const std::vector<uint8_t>& in, std::vector<uint8_t>& out) const override {
        out.resize(in.size());
        for (size_t i = 0; i < in.size(); i++) out[i] = in[i] ^ 0xAB;
    }
    void decryption(const std::vector<uint8_t>& in, std::vector<uint8_t>& out) const override {
        encryption(in, out);
    }
};

TEST_F(RasterImageFixture, LoadOperations) {
    {
        File::PNG png(validPngPath);
        png.load();
        EXPECT_EQ(static_cast<size_t>(300), png.get_size()) << "10x10 RGB PNG has 300 bytes";
    }
    {
        File::PNG png(smallPngPath);
        png.load();
        EXPECT_EQ(static_cast<size_t>(12), png.get_size()) << "2x2 RGB PNG has 12 bytes";
    }
    {
        File::PNG png(largePngPath);
        png.load();
        EXPECT_EQ(static_cast<size_t>(30000), png.get_size()) << "100x100 RGB PNG has 30000 bytes";
    }
    EXPECT_THROW({
        File::PNG png(nonexistentPath);
        png.load();
    }, std::runtime_error);
    EXPECT_THROW({
        File::PNG png(corruptPath);
        png.load();
    }, std::runtime_error);
    EXPECT_THROW({
        File::PNG png(emptyPath);
        png.load();
    }, std::runtime_error);
}

TEST_F(RasterImageFixture, SaveOperations) {
    // Save to explicit path — file exists and size matches after reload
    {
        File::PNG png(validPngPath);
        png.load();
        size_t original_size = png.get_size();

        fs::path outputPath = testDataDir / "output_save_test.png";
        png.save(outputPath);

        EXPECT_TRUE(fs::exists(outputPath)) << "Output file was created";

        File::PNG reloaded(outputPath);
        reloaded.load();
        EXPECT_EQ(original_size, reloaded.get_size())
            << "Reloaded file size matches original";

        fs::remove(outputPath);
    }

    // Save with empty path writes back to file_path
    {
        File::PNG png(validPngPath);
        png.load();
        std::vector<uint8_t> original = png.get_data();

        XorEncryptor xor_enc;
        png.apply_encryption(xor_enc);
        png.save();

        File::PNG reloaded(validPngPath);
        reloaded.load();
        EXPECT_NE(reloaded.get_data(), original)
            << "Save to original path persists the change";

        reloaded.apply_decryption(xor_enc);
        EXPECT_EQ(reloaded.get_data(), original)
            << "Decryption returns original data";
    }

    // Save to invalid directory throws
    EXPECT_THROW({
        File::PNG png(validPngPath);
        png.load();
        png.save("/invalid/nonexistent/directory/output.png");
    }, std::runtime_error);

    // Save without loading throws
    EXPECT_THROW({
        File::PNG png(validPngPath);
        png.save(testDataDir / "should_fail.png");
    }, std::logic_error);
}

TEST_F(RasterImageFixture, EdgeCases) {
    // Multiple loads on same object are consistent
    {
        File::PNG png(validPngPath);
        png.load();
        size_t firstLoad = png.get_size();
        png.load();
        size_t secondLoad = png.get_size();
        EXPECT_EQ(firstLoad, secondLoad) << "Multiple loads are consistent";
    }

    // Different image dimensions produce different byte counts
    {
        File::PNG small(smallPngPath);
        File::PNG large(largePngPath);
        small.load();
        large.load();
        EXPECT_TRUE(large.get_size() > small.get_size())
            << "100x100 PNG has more bytes than 2x2 PNG";
    }
}

TEST_F(RasterImageFixture, MemorySafety) {
    // Destructor after load does not crash
    {
        File::PNG png(validPngPath);
        png.load();
    }

    // Destructor without load does not crash
    {
        File::PNG png(validPngPath);
    }

    // Object remains valid after going out of scope in inner block
    {
        File::PNG outer(validPngPath);
        outer.load();
        size_t outerSize = outer.get_size();
        {
            File::PNG inner(smallPngPath);
            inner.load();
        }
        EXPECT_EQ(outerSize, outer.get_size())
            << "Outer PNG unaffected by inner scope destruction";
    }
}

TEST_F(RasterImageFixture, JpegLossyRoundTrip) {
    XorEncryptor xor_enc;

    // Encrypt → save JPEG → reload → JPEG altered the encrypted bytes
    {
        fs::path workPath = testDataDir / "jpeg_lossy_test1.jpg";
        fs::copy_file(validJpegPath, workPath, fs::copy_options::overwrite_existing);

        File::JPEG jpeg(workPath);
        jpeg.load();
        jpeg.apply_encryption(xor_enc);
        std::vector<uint8_t> encrypted = jpeg.get_data();

        jpeg.save();

        File::JPEG reloaded(workPath);
        reloaded.load();
        EXPECT_NE(reloaded.get_data(), encrypted)
            << "JPEG alters encrypted data during re-encoding (compression is lossy)";

        fs::remove(workPath);
    }

    // Encrypt → save JPEG → reload → decrypt ≠ original
    {
        fs::path workPath = testDataDir / "jpeg_lossy_test2.jpg";
        fs::copy_file(validJpegPath, workPath, fs::copy_options::overwrite_existing);

        File::JPEG jpeg(workPath);
        jpeg.load();
        std::vector<uint8_t> original = jpeg.get_data();

        jpeg.apply_encryption(xor_enc);
        jpeg.save();

        File::JPEG reloaded(workPath);
        reloaded.load();
        reloaded.apply_decryption(xor_enc);
        EXPECT_NE(reloaded.get_data(), original)
            << "decrypt(reload(encrypt(jpeg))) != original: JPEG is not a safe encrypted payload container";

        fs::remove(workPath);
    }
}
