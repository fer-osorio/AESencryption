add_library(ciphfortis_files STATIC
    src/file_base.cpp
    src/textf.cpp
    src/raster_image.cpp
    src/bitmap.cpp
    src/png_image.cpp
    src/jpeg_image.cpp
    src/image_factory.cpp
    src/stb_impl.cpp
)
# Suppress all warnings for the STB single-header wrapper (third-party code).
set_source_files_properties(src/stb_impl.cpp PROPERTIES COMPILE_FLAGS "-w")

target_include_directories(ciphfortis_files
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(ciphfortis_files
    PUBLIC  ciphfortis_core
            ciphfortis_analysis
    PRIVATE ciphfortis::compile_options
            third_party_stb
)
