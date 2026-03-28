find_program(CPPCHECK_PATH cppcheck)

if(CPPCHECK_PATH)
    file(GLOB_RECURSE _CIPHFORTIS_C_SOURCES
        "${CMAKE_SOURCE_DIR}/core-crypto/aes/src/*.c"
    )

    add_custom_target(lint-c
        COMMAND ${CPPCHECK_PATH}
            --enable=warning,performance,portability
            --std=c11
            --error-exitcode=1
            --suppress=missingIncludeSystem
            --quiet
            -I "${CMAKE_SOURCE_DIR}/core-crypto/aes/include"
            ${_CIPHFORTIS_C_SOURCES}
        COMMENT "cppcheck: linting C sources"
        VERBATIM
    )
    message(STATUS "cppcheck found — 'lint-c' target available")
else()
    message(STATUS "cppcheck not found — 'lint-c' target unavailable")
endif()
