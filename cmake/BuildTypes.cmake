set(CIPHFORTIS_BUILD_TYPE "test" CACHE STRING
    "Build type: debug | test | profile | release")
set_property(CACHE CIPHFORTIS_BUILD_TYPE PROPERTY STRINGS debug test profile release)

message(STATUS "CipherFortis build type: ${CIPHFORTIS_BUILD_TYPE}")

if(CIPHFORTIS_BUILD_TYPE STREQUAL "debug")
    # -O0, ASan/LSan/UBSan, ggdb3
    include(Sanitizers)
    set(_BT_FLAGS -O0 -ggdb3 -fno-omit-frame-pointer -fno-inline-functions-called-once
                  -fstack-protector-strong)
    set(_BT_LINK_FLAGS -fsanitize=address,leak,undefined)

elseif(CIPHFORTIS_BUILD_TYPE STREQUAL "test")
    # -O0, coverage
    set(_BT_FLAGS -O0 -g --coverage -fprofile-abs-path)
    set(_BT_LINK_FLAGS --coverage -fprofile-abs-path)
    include(Coverage)

elseif(CIPHFORTIS_BUILD_TYPE STREQUAL "profile")
    # -O2, gprof
    set(_BT_FLAGS -O2 -g -pg -fno-omit-frame-pointer)
    set(_BT_LINK_FLAGS -pg -fno-omit-frame-pointer)

else() # release
    # -O3, LTO
    set(_BT_FLAGS -O3 -DNDEBUG -march=native -flto)
    set(_BT_LINK_FLAGS -flto)
endif()

target_compile_options(ciphfortis_compile_options   INTERFACE ${_BT_FLAGS})
target_compile_options(ciphfortis_compile_options_c INTERFACE ${_BT_FLAGS})
target_link_options(ciphfortis_compile_options      INTERFACE ${_BT_LINK_FLAGS})
target_link_options(ciphfortis_compile_options_c    INTERFACE ${_BT_LINK_FLAGS})
