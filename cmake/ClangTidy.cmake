find_program(CLANG_TIDY_PATH clang-tidy)

if(CLANG_TIDY_PATH)
    # compile_commands.json is required by clang-tidy to resolve include paths.
    set(CMAKE_EXPORT_COMPILE_COMMANDS ON CACHE BOOL
        "Export compile commands for clang-tidy" FORCE)

    file(GLOB_RECURSE _CIPHFORTIS_CXX_SOURCES
        "${CMAKE_SOURCE_DIR}/core-crypto/src/*.cpp"
        "${CMAKE_SOURCE_DIR}/cli-tools/src/*.cpp"
        "${CMAKE_SOURCE_DIR}/file-handlers/src/*.cpp"
        "${CMAKE_SOURCE_DIR}/hsm-integration/src/*.cpp"
        "${CMAKE_SOURCE_DIR}/analysis/src/*.cpp"
        "${CMAKE_SOURCE_DIR}/command-line-tools/src/*.cpp"
    )

    add_custom_target(lint-cxx
        COMMAND ${CLANG_TIDY_PATH}
            -p ${CMAKE_BINARY_DIR}
            ${_CIPHFORTIS_CXX_SOURCES}
        COMMENT "clang-tidy: linting C++ sources"
        VERBATIM
    )
    message(STATUS "clang-tidy found — 'lint-cxx' target available")
else()
    message(STATUS "clang-tidy not found — 'lint-cxx' target unavailable")
endif()
