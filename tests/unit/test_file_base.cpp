// Unit test suite for FileBase contracts, exercised directly via File::FileBase
#include "../../file-handlers/include/file_base.hpp"
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
        File::FileBase fb(fixture.nonexistentPath);
        fb.load();
    }, "load() throws runtime_error for nonexistent file");

    PRINT_RESULTS();
    return SUITE_PASSED();
}

bool test_SizeAccessor(FileBaseFixture& fixture) {
    TEST_SUITE("Size Accessor Tests");

    // Test 1: get_size() returns the exact byte count written by the fixture
    RUN_TEST([&]() -> bool {
        File::FileBase fb(fixture.validFilePath);
        fb.load();
        return ASSERT_EQUAL(FILE_BASE_FIXTURE_FILE_SIZE, fb.get_size(),
                            "get_size() matches the number of bytes written by the fixture");
    }, "get_size() returns correct byte count after load");

    PRINT_RESULTS();
    return SUITE_PASSED();
}

bool test_EncryptionDecryption(FileBaseFixture& fixture) {
    TEST_SUITE("Encryption/Decryption Tests");

    XorEncryptor xor_enc;

    // Test 1: apply_encryption transforms data
    RUN_TEST([&]() -> bool {
        File::FileBase fb(fixture.validFilePath);
        fb.load();

        std::vector<uint8_t> original = fb.get_data();
        fb.apply_encryption(xor_enc);

        return ASSERT_TRUE(fb.get_data() != original, "Encrypted data differs from original");
    }, "apply_encryption transforms data");

    // Test 2: apply_decryption inverts encryption
    RUN_TEST([&]() -> bool {
        File::FileBase fb(fixture.validFilePath);
        fb.load();

        std::vector<uint8_t> original = fb.get_data();
        fb.apply_encryption(xor_enc);
        fb.apply_decryption(xor_enc);

        return ASSERT_TRUE(fb.get_data() == original, "Decrypt after encrypt restores original data");
    }, "apply_decryption inverts encryption");

    PRINT_RESULTS();
    return SUITE_PASSED();
}

bool test_SaveOperations(FileBaseFixture& fixture) {
    TEST_SUITE("Save Operation Tests");

    XorEncryptor xor_enc;

    // Test 1: save() with empty path writes back to file_path
    RUN_TEST([&]() -> bool {
        File::FileBase fb(fixture.validFilePath);
        fb.load();

        std::vector<uint8_t> original = fb.get_data();
        fb.apply_encryption(xor_enc);
        fb.save(); // write encrypted data back to validFilePath

        // Reload fresh instance and verify data changed
        File::FileBase reloaded(fixture.validFilePath);
        reloaded.load();

        bool dataChanged = ASSERT_TRUE(reloaded.get_data() != original,
                                       "Saved encrypted data differs from original");

        // Restore original data for subsequent tests
        reloaded.apply_decryption(xor_enc);
        reloaded.save();

        return dataChanged;
    }, "save() with empty path writes back to file_path");

    // Test 2: save() with explicit path writes to new location
    RUN_TEST([&]() -> bool {
        File::FileBase fb(fixture.validFilePath);
        fb.load();
        size_t original_size = fb.get_size();

        fs::path outputPath = fixture.testDataDir / "output.bin";
        fb.save(outputPath);

        bool fileExists = ASSERT_TRUE(fs::exists(outputPath), "Output file was created");

        File::FileBase reloaded(outputPath);
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
    std::cout << "                    FILE BASE CONTRACT TEST SUITE                               " << std::endl;
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
