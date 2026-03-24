# Shared C warning flags (BASE_CFLAGS equivalent)
set(_C_WARNINGS
    -Wall -Wextra -Wpedantic -Wformat=2 -Wcast-align -Wcast-qual
    -Wstrict-aliasing=2 -Wdisabled-optimization -Winit-self -Wlogical-op
    -Wmissing-declarations -Wmissing-include-dirs -Wredundant-decls
    -Wshadow -Wstrict-overflow=5 -Wundef -Wno-unused -Wno-variadic-macros
    -Wno-parentheses -fdiagnostics-show-option
)

# Additional C++ warning flags (BASE_CXXFLAGS additions)
set(_CXX_EXTRA_WARNINGS
    -Wctor-dtor-privacy -Wnoexcept -Wnon-virtual-dtor
    -Wstrict-null-sentinel -Wold-style-cast -Woverloaded-virtual -Wsign-promo
)

add_library(ciphfortis_compile_options   INTERFACE)
add_library(ciphfortis_compile_options_c INTERFACE)

add_library(ciphfortis::compile_options   ALIAS ciphfortis_compile_options)
add_library(ciphfortis::compile_options_c ALIAS ciphfortis_compile_options_c)

target_compile_options(ciphfortis_compile_options_c INTERFACE ${_C_WARNINGS})
target_compile_options(ciphfortis_compile_options   INTERFACE ${_C_WARNINGS} ${_CXX_EXTRA_WARNINGS})
