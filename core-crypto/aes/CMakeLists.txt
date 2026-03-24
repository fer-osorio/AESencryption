add_library(ciphfortis_aes STATIC
    src/AES.c
    src/block.c
    src/constants.c
    src/key_expansion.c
    src/operation_modes.c
)
target_include_directories(ciphfortis_aes
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_libraries(ciphfortis_aes
    PRIVATE ciphfortis::compile_options_c
)
