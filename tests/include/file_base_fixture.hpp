#ifndef FILE_BASE_FIXTURE_HPP
#define FILE_BASE_FIXTURE_HPP

#include <filesystem>
#include <cstdint>

namespace fs = std::filesystem;

struct FileBaseFixture {
    fs::path testDataDir     = fs::path("tests/data/file_base");
    fs::path validPngPath    = testDataDir / "valid_10x10.png";
    fs::path nonexistentPath = testDataDir / "does_not_exist.png";
    fs::path emptyDirPath    = testDataDir / "empty_subdir";

    FileBaseFixture();
    ~FileBaseFixture();

private:
    void setupTestEnvironment();
    void cleanupTestEnvironment();
    void createValidPng(const fs::path& path, int width, int height);
};

#endif // FILE_BASE_FIXTURE_HPP
