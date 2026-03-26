find_program(LCOV_PATH    lcov    REQUIRED)
find_program(GENHTML_PATH genhtml REQUIRED)

# Zero out .gcda counters without wiping .gcno files.
# Run this before re-executing tests to get an accurate fresh measurement.
add_custom_target(coverage-reset
    COMMAND ${LCOV_PATH}
        --zerocounters
        --directory ${CMAKE_BINARY_DIR}
    COMMENT "Resetting coverage counters"
    VERBATIM
)

# Run the full test suite, capture coverage, and render an HTML report.
# Usage: cmake --build build/test --target coverage
add_custom_target(coverage
    COMMAND ${CMAKE_CTEST_COMMAND}
        --test-dir ${CMAKE_BINARY_DIR}
        --output-on-failure
    COMMAND ${LCOV_PATH}
        --capture
        --directory ${CMAKE_BINARY_DIR}
        --output-file ${CMAKE_BINARY_DIR}/coverage.info
        --exclude "*/test-vectors/*"
        --exclude "*/third-party/*"
        --exclude "*/tests/*"
        --exclude "/usr/*"
    COMMAND ${GENHTML_PATH}
        ${CMAKE_BINARY_DIR}/coverage.info
        --output-directory ${CMAKE_BINARY_DIR}/coverage-report
        --demangle-cpp
    COMMENT "Coverage report -> ${CMAKE_BINARY_DIR}/coverage-report/index.html"
    VERBATIM
)
