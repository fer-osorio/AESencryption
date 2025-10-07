#include<filesystem> // For path handling

namespace fs = std::filesystem;

// ============================================================================
// Test Fixture - Manages test data and helper functions
// ============================================================================
class BitmapTestFixture {
public:
    // Test file paths
    const fs::path testDataDir = "test_data";
    const fs::path validBmpPath = testDataDir / "valid_24bit.bmp";
    const fs::path smallBmpPath = testDataDir / "small_2x2.bmp";
    const fs::path largeBmpPath = testDataDir / "large_100x100.bmp";
    const fs::path corruptHeaderPath = testDataDir / "corrupt_header.bmp";
    const fs::path wrongMagicPath = testDataDir / "wrong_magic.bmp";
    const fs::path unsupportedBitDepthPath = testDataDir / "16bit.bmp";
    const fs::path nonexistentPath = testDataDir / "does_not_exist.bmp";

    BitmapTestFixture();
    ~BitmapTestFixture();

private:
    void setupTestEnvironment();

    void cleanupTestEnvironment();

    // Creates a minimal valid 24-bit BMP file
    void createValidBitmap(const fs::path& path, int width, int height);

    // Creates a BMP with corrupt header
    void createCorruptBitmap(const fs::path& path);

    // Creates a file with wrong magic bytes
    void createWrongMagicBitmap(const fs::path& path);

    // Helper functions to write binary data
    void writeInt16(std::ofstream& file, int16_t value);

    void writeInt32(std::ofstream& file, int32_t value);
};  // class BitmapTestFixture