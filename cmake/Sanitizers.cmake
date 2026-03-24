# ASan/LSan/UBSan — appended to both interface libraries
foreach(_target ciphfortis_compile_options ciphfortis_compile_options_c)
    target_compile_options(${_target} INTERFACE
        -fsanitize=address,leak,undefined)
    target_link_options(${_target} INTERFACE
        -fsanitize=address,leak,undefined)
endforeach()
