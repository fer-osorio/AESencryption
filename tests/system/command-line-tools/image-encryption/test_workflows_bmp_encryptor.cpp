// System/E2E Testing Examples for AES File Encryption Tool
// File: system/test_file_encryption_workflows.cpp

#include "../../../include/test_framework.hpp"
#include "../../test_workflows.hpp"
#include <filesystem>
#include <fstream>
#include <cstdlib>
#include <string>

#define BMP_ENCRYPTOR ../../../../bin/command-line-tools/image-encryption/bmp_encryptor

namespace su = CommandLineToolsTest::SystemUtils;

int main() {
    std::cout << "=== System/E2E Testing for AES File Encryption Tool ===" << std::endl;

    test_image_encryption_workflow();
    test_error_scenarios();
    test_large_file_performance();

    std::cout << "\n=== All System Tests Complete ===" << std::endl;
    return 0;
}
