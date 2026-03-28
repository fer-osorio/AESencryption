// Unit test suite for FileBase contracts, exercised directly via File::FileBase
#include <gtest/gtest.h>
#include "../../file-handlers/include/file_base.hpp"
#include "../include/file_base_fixture.hpp"
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

TEST_F(FileBaseFixture, LoadOperations) {
    EXPECT_THROW({
        File::FileBase fb(nonexistentPath);
        fb.load();
    }, std::runtime_error);
}

TEST_F(FileBaseFixture, SizeAccessor) {
    File::FileBase fb(validFilePath);
    fb.load();
    EXPECT_EQ(FILE_BASE_FIXTURE_FILE_SIZE, fb.get_size())
        << "get_size() matches the number of bytes written by the fixture";
}

TEST_F(FileBaseFixture, EncryptionDecryption) {
    XorEncryptor xor_enc;

    {
        File::FileBase fb(validFilePath);
        fb.load();
        std::vector<uint8_t> original = fb.get_data();
        fb.apply_encryption(xor_enc);
        EXPECT_NE(fb.get_data(), original) << "Encrypted data differs from original";
    }

    {
        File::FileBase fb(validFilePath);
        fb.load();
        std::vector<uint8_t> original = fb.get_data();
        fb.apply_encryption(xor_enc);
        fb.apply_decryption(xor_enc);
        EXPECT_EQ(fb.get_data(), original) << "Decrypt after encrypt restores original data";
    }
}

TEST_F(FileBaseFixture, SaveOperations) {
    XorEncryptor xor_enc;

    // save() with empty path writes back to file_path
    {
        File::FileBase fb(validFilePath);
        fb.load();
        std::vector<uint8_t> original = fb.get_data();
        fb.apply_encryption(xor_enc);
        fb.save();

        File::FileBase reloaded(validFilePath);
        reloaded.load();
        EXPECT_NE(reloaded.get_data(), original)
            << "Saved encrypted data differs from original";
    }

    // save() with explicit path writes to new location
    {
        File::FileBase fb(validFilePath);
        fb.load();
        size_t original_size = fb.get_size();

        fs::path outputPath = testDataDir / "output.bin";
        fb.save(outputPath);

        EXPECT_TRUE(fs::exists(outputPath)) << "Output file was created";

        File::FileBase reloaded(outputPath);
        reloaded.load();
        EXPECT_EQ(original_size, reloaded.get_size())
            << "Reloaded file size matches original";

        fs::remove(outputPath);
    }
}
