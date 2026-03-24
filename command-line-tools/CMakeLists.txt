if(TARGET ciphfortis_hsm)
    add_executable(hsm-encrypt hsm-encrypt/hsm_encrypt.cpp)
    target_link_libraries(hsm-encrypt PRIVATE
        ciphfortis_cli ciphfortis_files ciphfortis_core
        ciphfortis_aes ciphfortis_analysis ciphfortis_hsm
        ciphfortis::compile_options ${CMAKE_DL_LIBS}
    )
    set_target_properties(hsm-encrypt PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/command-line-tools)
endif()

add_executable(image-encryptor image-encryption/image_encryptor.cpp)
target_link_libraries(image-encryptor PRIVATE
    ciphfortis_cli ciphfortis_files ciphfortis_core
    ciphfortis_aes ciphfortis_analysis
    ciphfortis::compile_options ${CMAKE_DL_LIBS}
)
set_target_properties(image-encryptor PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/command-line-tools)
