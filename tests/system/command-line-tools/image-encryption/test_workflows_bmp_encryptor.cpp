// System/E2E Testing Examples for AES File Encryption Tool
// File: system/test_file_encryption_workflows.cpp

//#include "../../../include/test_framework.hpp"
#include "../../../include/system_workflows.hpp"
#include <filesystem>
#include <fstream>
#include <cstdlib>
#include <string>

#define BMP_ENCRYPTOR ../../../../bin/command-line-tools/image-encryption/bmp_encryptor

namespace cltt = CommandLineToolsTest;

int main() {
    std::cout << "=== System/E2E Testing for AES File Encryption Tool ===" << std::endl;

    cltt::SystemTests st("BMP_ENCRYPTOR", cltt::FileFormat::BITMAP);
    st.test_file_encryption_workflow();
    st.test_error_scenarios();
    st.test_large_file_performance();

    std::cout << "\n=== All System Tests Complete ===" << std::endl;
    return 0;
}
