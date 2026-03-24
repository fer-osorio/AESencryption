find_program(LCOV_PATH  lcov  REQUIRED)
find_program(GENHTML_PATH genhtml REQUIRED)

add_custom_target(coverage
    COMMAND ${LCOV_PATH} --capture
        --directory ${CMAKE_BINARY_DIR}
        --output-file ${CMAKE_BINARY_DIR}/coverage.info
        --exclude "*/test-vectors/*"
        --exclude "*/third-party/*"
        --exclude "*/tests/*"
    COMMAND ${GENHTML_PATH} ${CMAKE_BINARY_DIR}/coverage.info
        --output-directory ${CMAKE_BINARY_DIR}/coverage-report
    COMMENT "Generating coverage HTML report -> ${CMAKE_BINARY_DIR}/coverage-report/index.html"
    VERBATIM
)
