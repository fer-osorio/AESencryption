#ifndef FILE_BASE_FIXTURE_HPP
#define FILE_BASE_FIXTURE_HPP

#include <filesystem>
#include <cstdint>

namespace fs = std::filesystem;

// Number of bytes written by the fixture's binary test asset.
static constexpr size_t FILE_BASE_FIXTURE_FILE_SIZE = 64;

struct FileBaseFixture {
    fs::path testDataDir     = fs::path("tests/data/file_base");
    fs::path validFilePath   = testDataDir / "valid_64bytes.bin";
    fs::path nonexistentPath = testDataDir / "does_not_exist.bin";

    FileBaseFixture();
    ~FileBaseFixture();

private:
    void setupTestEnvironment();
    void cleanupTestEnvironment();
    void createBinaryFile(const fs::path& path, size_t size);
};

#endif // FILE_BASE_FIXTURE_HPP
