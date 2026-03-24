add_library(third_party_stb INTERFACE)
target_include_directories(third_party_stb INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/stb
)
