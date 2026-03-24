find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(P11KIT QUIET p11-kit-1)
endif()

if(NOT P11KIT_FOUND)
    message(STATUS "ciphfortis_hsm: p11-kit-1 not found — skipping HSM module")
    return()
endif()

add_library(ciphfortis_hsm STATIC
    src/hsm_session.cpp
    src/hsm_cipher.cpp
    src/hsm_key_handle.cpp
)
target_include_directories(ciphfortis_hsm
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${P11KIT_INCLUDE_DIRS}
)
target_link_libraries(ciphfortis_hsm
    PUBLIC  ciphfortis_core
    PRIVATE ciphfortis::compile_options
            ${P11KIT_LIBRARIES}
)
