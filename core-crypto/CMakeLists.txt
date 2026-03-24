add_subdirectory(aes)

add_library(ciphfortis_core STATIC
    src/core/cipher.cpp
    src/core/key.cpp
)
target_include_directories(ciphfortis_core
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/utils
)
target_link_libraries(ciphfortis_core
    PUBLIC  ciphfortis_aes
    PRIVATE ciphfortis::compile_options
)
