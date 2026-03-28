# ── Shared fixture library ────────────────────────────────────────────────────
add_library(ciphfortis_test_fixtures STATIC
    src/file_base_fixture.cpp
    src/raster_image_fixture.cpp
    src/system_workflows.cpp
)
target_include_directories(ciphfortis_test_fixtures PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(ciphfortis_test_fixtures
    PUBLIC  ciphfortis_files ciphfortis_core ciphfortis_aes
            ciphfortis_analysis ciphfortis_testing GTest::gtest
    PRIVATE ciphfortis::compile_options
)

# ── Helper function ───────────────────────────────────────────────────────────
function(add_ciphfortis_test)
    cmake_parse_arguments(ARG "" "NAME;LABEL" "SOURCES;EXTRA_LIBS" ${ARGN})

    add_executable(${ARG_NAME} ${ARG_SOURCES})
    target_link_libraries(${ARG_NAME} PRIVATE
        ciphfortis_testing GTest::gtest_main
        ciphfortis::compile_options
        ${ARG_EXTRA_LIBS}
    )
    set_target_properties(${ARG_NAME} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY
            ${CMAKE_BINARY_DIR}/tests/bin/${ARG_LABEL}
    )
    gtest_discover_tests(${ARG_NAME}
        PROPERTIES
            LABELS            ${ARG_LABEL}
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/tests
    )
endfunction()

# ── Unit tests ────────────────────────────────────────────────────────────────
add_ciphfortis_test(NAME test_AES              SOURCES unit/test_AES.cpp
    LABEL unit EXTRA_LIBS ciphfortis_aes)
add_ciphfortis_test(NAME test_cipher           SOURCES unit/test_cipher.cpp
    LABEL unit EXTRA_LIBS ciphfortis_core ciphfortis_aes)
add_ciphfortis_test(NAME test_key              SOURCES unit/test_key.cpp
    LABEL unit EXTRA_LIBS ciphfortis_core ciphfortis_aes)
add_ciphfortis_test(NAME test_operation_modes  SOURCES unit/test_operation_modes.cpp
    LABEL unit EXTRA_LIBS ciphfortis_core ciphfortis_aes)
add_ciphfortis_test(NAME test_file_base        SOURCES unit/test_file_base.cpp
    LABEL unit
    EXTRA_LIBS ciphfortis_files ciphfortis_core ciphfortis_aes
               ciphfortis_analysis ciphfortis_test_fixtures)
add_ciphfortis_test(NAME test_raster_image     SOURCES unit/test_raster_image.cpp
    LABEL unit
    EXTRA_LIBS ciphfortis_files ciphfortis_core ciphfortis_aes
               ciphfortis_analysis ciphfortis_test_fixtures)

if(TARGET ciphfortis_hsm)
    add_ciphfortis_test(NAME test_hsmcipher    SOURCES unit/test_hsmcipher.cpp
        LABEL unit
        EXTRA_LIBS ciphfortis_hsm ciphfortis_core ciphfortis_aes ${CMAKE_DL_LIBS})
endif()

# ── Integration tests ─────────────────────────────────────────────────────────
add_ciphfortis_test(NAME test_cpp_c_interface    SOURCES integration/test_cpp_c_interface.cpp
    LABEL integration EXTRA_LIBS ciphfortis_core ciphfortis_aes)
add_ciphfortis_test(NAME test_cli_crypto_config  SOURCES integration/test_cli_crypto_config.cpp
    LABEL integration EXTRA_LIBS ciphfortis_cli ciphfortis_core ciphfortis_aes)

# ── System tests ──────────────────────────────────────────────────────────────
add_ciphfortis_test(NAME test_image_encryptorcpp SOURCES system/test_image_encryptorcpp.cpp
    LABEL system
    EXTRA_LIBS ciphfortis_files ciphfortis_core ciphfortis_aes
               ciphfortis_analysis ciphfortis_test_fixtures)
target_compile_definitions(test_image_encryptorcpp PRIVATE
    IMAGE_ENCRYPTOR_PATH="$<TARGET_FILE:image-encryptor>"
)

# ── Convenience targets ───────────────────────────────────────────────────────
add_custom_target(run-unit
    COMMAND ${CMAKE_CTEST_COMMAND} -L unit --output-on-failure
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
add_custom_target(run-integration
    COMMAND ${CMAKE_CTEST_COMMAND} -L integration --output-on-failure
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
add_custom_target(run-system
    COMMAND ${CMAKE_CTEST_COMMAND} -L system --output-on-failure
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
