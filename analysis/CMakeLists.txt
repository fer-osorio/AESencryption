add_library(ciphfortis_analysis STATIC
    src/data_randomness.cpp
)
target_include_directories(ciphfortis_analysis
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(ciphfortis_analysis
    PRIVATE ciphfortis::compile_options
)
