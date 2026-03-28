add_library(ciphfortis_testing STATIC
    src/test-vectors/common.cpp
    src/test-vectors/fips197_cipher.cpp
    src/test-vectors/fips197_key_expansion.cpp
    src/test-vectors/keys.cpp
    src/test-vectors/sp800_38a_modes.cpp
    src/test-vectors/stub_data.cpp
)
target_include_directories(ciphfortis_testing
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(ciphfortis_testing
    PUBLIC  ciphfortis_core
            ciphfortis_aes
    PRIVATE ciphfortis::compile_options
)
