// System/E2E Testing Examples for AES File Encryption Tool

#include "../include/system_workflows.hpp"
#include <filesystem>
#include <limits.h>             // For PATH_MAX

#ifdef __linux__
    #include <unistd.h>         // For readlink
#elif __APPLE__ || __MACH__
    #include <mach-o/dyld.h>    // For _NSGetExecutablePath
#elif _WIN32 || _WIN64
    #include <windows.h>        // For GetModuleFileNameA
#endif

const std::filesystem::path findProjectRoot();

#define BMP_ENCRYPTOR "bin/command-line-tools/image-encryption/bmp_encryptor"

namespace cltt = CommandLineToolsTest;

int main() {
    std::cout << "=== System/E2E Testing for AES File Encryption Tool ===" << std::endl;

    std::filesystem::path bmp_encryptor_path = findProjectRoot() / BMP_ENCRYPTOR;

    try{
        cltt::SystemTests st(bmp_encryptor_path.string(), cltt::FileFormat::BITMAP);
        st.test_file_encryption_workflow();
        st.test_error_scenarios();
        st.test_large_file_performance();
    } catch(const std::exception& e){
        std::cerr << e.what();
    }

    std::cout << "\n=== All System Tests Complete ===" << std::endl;
    return 0;
}

const std::filesystem::path findProjectRoot() {
    char buffpath[PATH_MAX];
    bool pathRetrieveFailed = false;
    #ifdef __linux__
        ssize_t len = readlink(                                                 // Gets this executable path
            "/proc/self/exe", buffpath, sizeof(buffpath) - 1                    // "/proc/self/exe" is a symbolic link to this executable
        );
        if (len != -1) {
            buffpath[len] = 0;
        } else pathRetrieveFailed = true;
    #elif __APPLE__ || __MACH__
        if(_NSGetExecutablePath(path_buffer, &size) != 0) {
            pathRetrieveFailed = true;
        }
    #elif _WIN32 || _WIN64
        DWORD length = GetModuleFileNameW(NULL, buffpath, PATH_MAX);
        if(length <= 0) pathRetrieveFailed = true;
    #endif

    if (pathRetrieveFailed){
        return {};                                                              // Failure: Executable path not found.
    }

    std::filesystem::path executablePath(buffpath);
    std::filesystem::path currentPath = executablePath.parent_path();
    while (currentPath.has_parent_path()) {
        if (std::filesystem::exists(currentPath / "common.mk") ||
            std::filesystem::exists(currentPath / ".git/config")) {
            return currentPath;
        }
        currentPath = currentPath.parent_path();
    }
    return {}; // Not found
}
