cmake_minimum_required(VERSION 3.25)
project(CipherFortis VERSION 0.1.0 LANGUAGES C CXX)

# Prevent in-source builds
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
    message(FATAL_ERROR
        "In-source builds are not allowed. "
        "Run cmake from a build directory, e.g.:\n"
        "  cmake --preset test")
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

include(CompilerWarnings)
include(BuildTypes)
include(GTest)
include(Cppcheck)
include(ClangTidy)

include(CTest)
enable_testing()

add_subdirectory(third-party)
add_subdirectory(core-crypto)
add_subdirectory(analysis)
add_subdirectory(cli-tools)
add_subdirectory(file-handlers)
add_subdirectory(hsm-integration)
add_subdirectory(testing)
add_subdirectory(command-line-tools)
add_subdirectory(tests)
