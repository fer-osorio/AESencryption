// Unit test suite for FileBase contracts, exercised via File::PNG
#include "../../file-handlers/include/png_image.hpp"
#include "../include/file_base_fixture.hpp"
#include "../../test-framework/include/test_framework.hpp"
#include "../../include/encryptor.hpp"
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
        encryption(in, out); // XOR is its own inverse
    }
};

// ============================================================================
// Test Suite Functions
// ============================================================================

bool test_LoadOperations(FileBaseFixture& fixture);
bool test_SizeAccessor(FileBaseFixture& fixture);
bool test_EncryptionDecryption(FileBaseFixture& fixture);
bool test_SaveOperations(FileBaseFixture& fixture);
bool runAllTests();

int main() { return runAllTests() ? 0 : 1; }

bool test_LoadOperations(FileBaseFixture& fixture) {
    TEST_SUITE("Load Operation Tests");

    // Test 1: load() throws on missing file
    ASSERT_THROWS(std::runtime_error, [&]() {
        File::PNG png(fixture.nonexistentPath);
        png.load();
    }, "load() throws runtime_error for nonexistent file");

    PRINT_RESULTS();
    return SUITE_PASSED();
}

bool test_SizeAccessor(FileBaseFixture& fixture) {
    TEST_SUITE("Size Accessor Tests");

    // Test 1: get_size() returns correct byte count after loading
    RUN_TEST([&]() -> bool {
        File::PNG png(fixture.validPngPath);
        png.load();
        // 10x10 RGB image = 300 bytes
        return ASSERT_EQUAL(static_cast<size_t>(300), png.get_size(), "10x10 RGB PNG has 300 bytes");
    }, "get_size() returns 300 for 10x10 RGB PNG");

    PRINT_RESULTS();
    return SUITE_PASSED();
}

bool test_EncryptionDecryption(FileBaseFixture& fixture) {
    TEST_SUITE("Encryption/Decryption Tests");

    XorEncryptor xor_enc;

    // Test 1: apply_encryption transforms data
    RUN_TEST([&]() -> bool {
        File::PNG png(fixture.validPngPath);
        png.load();

        std::vector<uint8_t> original = png.get_data();
        png.apply_encryption(xor_enc);

        return ASSERT_TRUE(png.get_data() != original, "Encrypted data differs from original");
    }, "apply_encryption transforms data");

    // Test 2: apply_decryption inverts encryption
    RUN_TEST([&]() -> bool {
        File::PNG png(fixture.validPngPath);
        png.load();

        std::vector<uint8_t> original = png.get_data();
        png.apply_encryption(xor_enc);
        png.apply_decryption(xor_enc);

        return ASSERT_TRUE(png.get_data() == original, "Decrypt after encrypt restores original data");
    }, "apply_decryption inverts encryption");

    PRINT_RESULTS();
    return SUITE_PASSED();
}

bool test_SaveOperations(FileBaseFixture& fixture) {
    TEST_SUITE("Save Operation Tests");

    XorEncryptor xor_enc;

    // Test 1: save() with empty path writes back to file_path
    RUN_TEST([&]() -> bool {
        File::PNG png(fixture.validPngPath);
        png.load();

        std::vector<uint8_t> original = png.get_data();
        png.apply_encryption(xor_enc);
        png.save(); // save to original path

        // Reload fresh instance and verify data changed
        File::PNG reloaded(fixture.validPngPath);
        reloaded.load();

        bool dataChanged = ASSERT_TRUE(reloaded.get_data() != original,
                                       "Saved encrypted data differs from original");

        // Restore original data for other tests
        reloaded.apply_decryption(xor_enc);
        reloaded.save();

        return dataChanged;
    }, "save() with empty path writes back to file_path");

    // Test 2: save() with explicit path writes to new location
    RUN_TEST([&]() -> bool {
        File::PNG png(fixture.validPngPath);
        png.load();
        size_t original_size = png.get_size();

        fs::path outputPath = fixture.testDataDir / "output.png";
        png.save(outputPath);

        bool fileExists = ASSERT_TRUE(fs::exists(outputPath), "Output file was created");

        File::PNG reloaded(outputPath);
        reloaded.load();
        bool sizeMatches = ASSERT_EQUAL(original_size, reloaded.get_size(),
                                        "Reloaded file size matches original");

        fs::remove(outputPath);
        return fileExists && sizeMatches;
    }, "save() with explicit path writes to new location");

    PRINT_RESULTS();
    return SUITE_PASSED();
}

bool runAllTests() {
    std::cout << "================================================================================" << std::endl;
    std::cout << "               FILE BASE CONTRACT TEST SUITE (via File::PNG)                   " << std::endl;
    std::cout << "================================================================================" << std::endl;

    TEST_SUITE("FileBase Comprehensive Tests");
    FileBaseFixture fixture;
    std::cout << "\n";

    RUN_TEST([&]() -> bool {
        return test_LoadOperations(fixture);
    }, "Load Operations");
    std::cout << "================================================================================\n\n";

    RUN_TEST([&]() -> bool {
        return test_SizeAccessor(fixture);
    }, "Size Accessor");
    std::cout << "================================================================================\n\n";

    RUN_TEST([&]() -> bool {
        return test_EncryptionDecryption(fixture);
    }, "Encryption/Decryption");
    std::cout << "================================================================================\n\n";

    RUN_TEST([&]() -> bool {
        return test_SaveOperations(fixture);
    }, "Save Operations");

    std::cout << "\n================================================================================" << std::endl;
    PRINT_RESULTS();
    std::cout << "================================================================================" << std::endl;

    return SUITE_PASSED();
}
