// Unit test suite for RasterImage contracts, exercised via File::PNG and File::JPEG
#include "../../file-handlers/include/png_image.hpp"
#include "../../file-handlers/include/jpeg_image.hpp"
#include "../include/raster_image_fixture.hpp"
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

bool test_LoadOperations(RasterImageFixture& fixture);
bool test_SaveOperations(RasterImageFixture& fixture);
bool test_EdgeCases(RasterImageFixture& fixture);
bool test_MemorySafety(RasterImageFixture& fixture);
bool test_JpegLossyRoundTrip(RasterImageFixture& fixture);
bool runAllTests();

int main() { return runAllTests() ? 0 : 1; }

bool test_LoadOperations(RasterImageFixture& fixture) {
    TEST_SUITE("Load Operation Tests");

    // Test 1: Load valid 10x10 PNG — size is width * height * channels
    RUN_TEST([&]() -> bool {
        File::PNG png(fixture.validPngPath);
        png.load();
        return ASSERT_EQUAL(static_cast<size_t>(300), png.get_size(), "10x10 RGB PNG has 300 bytes");
    }, "Load valid 10x10 PNG");

    // Test 2: Load small 2x2 PNG
    RUN_TEST([&]() -> bool {
        File::PNG png(fixture.smallPngPath);
        png.load();
        return ASSERT_EQUAL(static_cast<size_t>(12), png.get_size(), "2x2 RGB PNG has 12 bytes");
    }, "Load small 2x2 PNG");

    // Test 3: Load large 100x100 PNG
    RUN_TEST([&]() -> bool {
        File::PNG png(fixture.largePngPath);
        png.load();
        return ASSERT_EQUAL(static_cast<size_t>(30000), png.get_size(), "100x100 RGB PNG has 30000 bytes");
    }, "Load large 100x100 PNG");

    // Test 4: Load nonexistent file throws
    ASSERT_THROWS(std::runtime_error, [&]() {
        File::PNG png(fixture.nonexistentPath);
        png.load();
    }, "load() throws runtime_error for nonexistent file");

    // Test 5: Load corrupt file throws
    ASSERT_THROWS(std::runtime_error, [&]() {
        File::PNG png(fixture.corruptPath);
        png.load();
    }, "load() throws runtime_error for corrupt file");

    // Test 6: Load empty file throws
    ASSERT_THROWS(std::runtime_error, [&]() {
        File::PNG png(fixture.emptyPath);
        png.load();
    }, "load() throws runtime_error for empty file");

    PRINT_RESULTS();
    return SUITE_PASSED();
}

bool test_SaveOperations(RasterImageFixture& fixture) {
    TEST_SUITE("Save Operation Tests");

    // Test 1: Save PNG to explicit path — file exists and size matches after reload
    RUN_TEST([&]() -> bool {
        File::PNG png(fixture.validPngPath);
        png.load();
        size_t original_size = png.get_size();

        fs::path outputPath = fixture.testDataDir / "output_save_test.png";
        png.save(outputPath);

        bool fileExists = ASSERT_TRUE(fs::exists(outputPath), "Output file was created");

        File::PNG reloaded(outputPath);
        reloaded.load();
        bool sizeMatches = ASSERT_EQUAL(original_size, reloaded.get_size(),
                                        "Reloaded file size matches original");

        fs::remove(outputPath);
        return fileExists && sizeMatches;
    }, "Save to explicit path and reload preserves size");

    // Test 2: Save with empty path writes back to file_path
    RUN_TEST([&]() -> bool {
        File::PNG png(fixture.validPngPath);
        png.load();
        std::vector<uint8_t> original = png.get_data();

        XorEncryptor xor_enc;
        png.apply_encryption(xor_enc);
        png.save(); // write encrypted data back to validPngPath

        File::PNG reloaded(fixture.validPngPath);
        reloaded.load();
        bool dataChanged = ASSERT_TRUE(reloaded.get_data() != original,
                                       "Save to original path persists the change");

        // Verify if decryption works
        reloaded.apply_decryption(xor_enc);
        bool dataRecoverd = ASSERT_TRUE(reloaded.get_data() == original,
                                       "Decryption returns original data");
        reloaded.save();

        return dataChanged && dataRecoverd;
    }, "Save with empty path writes back to file_path");

    // Test 3: Save to invalid directory throws
    ASSERT_THROWS(std::runtime_error, [&]() {
        File::PNG png(fixture.validPngPath);
        png.load();
        png.save("/invalid/nonexistent/directory/output.png");
    }, "Save to invalid directory throws runtime_error");

    // Test 4: Save without loading throws (width_/height_ are 0 → stbi_write_png fails)
    ASSERT_THROWS(std::logic_error, [&]() {
        File::PNG png(fixture.validPngPath);
        png.save(fixture.testDataDir / "should_fail.png");
    }, "Save without load throws logic_error");

    PRINT_RESULTS();
    return SUITE_PASSED();
}

bool test_EdgeCases(RasterImageFixture& fixture) {
    TEST_SUITE("Edge Case Tests");

    // Test 1: Multiple loads on same object are consistent
    RUN_TEST([&]() -> bool {
        File::PNG png(fixture.validPngPath);
        png.load();
        size_t firstLoad = png.get_size();
        png.load(); // second load — RasterImage guards against double-load
        size_t secondLoad = png.get_size();
        return ASSERT_EQUAL(firstLoad, secondLoad, "Multiple loads are consistent");
    }, "Multiple loads on same PNG are consistent");

    // Test 2: Different image dimensions produce different byte counts
    RUN_TEST([&]() -> bool {
        File::PNG small(fixture.smallPngPath);
        File::PNG large(fixture.largePngPath);
        small.load();
        large.load();
        return ASSERT_TRUE(large.get_size() > small.get_size(),
                           "100x100 PNG has more bytes than 2x2 PNG");
    }, "Different dimensions produce different sizes");

    PRINT_RESULTS();
    return SUITE_PASSED();
}

bool test_MemorySafety(RasterImageFixture& fixture) {
    TEST_SUITE("Memory Safety Tests");

    // Test 1: Destructor after load does not crash
    RUN_TEST([&]() -> bool {
        {
            File::PNG png(fixture.validPngPath);
            png.load();
        } // destructor called here
        return true;
    }, "Destructor after load does not crash");

    // Test 2: Destructor without load does not crash
    RUN_TEST([&]() -> bool {
        {
            File::PNG png(fixture.validPngPath);
        } // destructor without load
        return true;
    }, "Destructor without load does not crash");

    // Test 3: Object remains valid after going out of scope in inner block
    RUN_TEST([&]() -> bool {
        File::PNG outer(fixture.validPngPath);
        outer.load();
        size_t outerSize = outer.get_size();
        {
            File::PNG inner(fixture.smallPngPath);
            inner.load();
        } // inner destructor
        return ASSERT_EQUAL(outerSize, outer.get_size(),
                            "Outer PNG unaffected by inner scope destruction");
    }, "Outer PNG unaffected by inner scope destruction");

    PRINT_RESULTS();
    return SUITE_PASSED();
}

bool test_JpegLossyRoundTrip(RasterImageFixture& fixture) {
    TEST_SUITE("JPEG Lossy Round-Trip Tests");

    XorEncryptor xor_enc;

    // Both tests work on isolated copies so validJpegPath is never modified.

    // Test 1: Encrypt → save JPEG → reload → JPEG altered the encrypted bytes
    // Documents that JPEG compression changes pixel data (it is lossy).
    RUN_TEST([&]() -> bool {
        fs::path workPath = fixture.testDataDir / "jpeg_lossy_test1.jpg";
        fs::copy_file(fixture.validJpegPath, workPath,
                      fs::copy_options::overwrite_existing);

        File::JPEG jpeg(workPath);
        jpeg.load();
        jpeg.apply_encryption(xor_enc);
        std::vector<uint8_t> encrypted = jpeg.get_data();

        jpeg.save(); // JPEG re-encodes high-entropy encrypted data

        File::JPEG reloaded(workPath);
        reloaded.load();

        bool altered = ASSERT_TRUE(reloaded.get_data() != encrypted,
            "JPEG alters encrypted data during re-encoding (compression is lossy)");

        fs::remove(workPath);
        return altered;
    }, "JPEG re-encodes encrypted data lossily");

    // Test 2: Encrypt → save JPEG → reload → decrypt ≠ original
    // Key assertion: JPEG cannot faithfully preserve encrypted payloads.
    RUN_TEST([&]() -> bool {
        fs::path workPath = fixture.testDataDir / "jpeg_lossy_test2.jpg";
        fs::copy_file(fixture.validJpegPath, workPath,
                      fs::copy_options::overwrite_existing);

        File::JPEG jpeg(workPath);
        jpeg.load();
        std::vector<uint8_t> original = jpeg.get_data();

        jpeg.apply_encryption(xor_enc);
        jpeg.save();

        File::JPEG reloaded(workPath);
        reloaded.load();
        reloaded.apply_decryption(xor_enc);

        bool roundTripFails = ASSERT_TRUE(reloaded.get_data() != original,
            "decrypt(reload(encrypt(jpeg))) != original: JPEG is not a safe encrypted payload container");

        fs::remove(workPath);
        return roundTripFails;
    }, "JPEG encrypt/save/reload/decrypt does not restore original data");

    PRINT_RESULTS();
    return SUITE_PASSED();
}

bool runAllTests() {
    std::cout << "================================================================================" << std::endl;
    std::cout << "            RASTER IMAGE CONTRACT TEST SUITE (PNG + JPEG)                      " << std::endl;
    std::cout << "================================================================================" << std::endl;

    TEST_SUITE("RasterImage Comprehensive Tests");
    RasterImageFixture fixture;
    std::cout << "\n";

    RUN_TEST([&]() -> bool {
        return test_LoadOperations(fixture);
    }, "Load Operations");
    std::cout << "================================================================================\n\n";

    RUN_TEST([&]() -> bool {
        return test_SaveOperations(fixture);
    }, "Save Operations");
    std::cout << "================================================================================\n\n";

    RUN_TEST([&]() -> bool {
        return test_EdgeCases(fixture);
    }, "Edge Cases");
    std::cout << "================================================================================\n\n";

    RUN_TEST([&]() -> bool {
        return test_MemorySafety(fixture);
    }, "Memory Safety");
    std::cout << "================================================================================\n\n";

    RUN_TEST([&]() -> bool {
        return test_JpegLossyRoundTrip(fixture);
    }, "JPEG Lossy Round-Trip");

    std::cout << "\n================================================================================" << std::endl;
    PRINT_RESULTS();
    std::cout << "================================================================================" << std::endl;

    return SUITE_PASSED();
}
