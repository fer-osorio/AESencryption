add_library(ciphfortis_cli STATIC
    src/cli_config.cpp
)
target_include_directories(ciphfortis_cli
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(ciphfortis_cli
    PUBLIC  ciphfortis_core
    PRIVATE ciphfortis::compile_options
)
