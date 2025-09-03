# config.mk - Project-wide configuration
# This file contains compiler settings and project-specific configurations
# Include this file in common.mk and other Makefiles that need these settings

# Project information
PROJECT_NAME = aes-encryption-research
VERSION = 1.0.0
AUTHOR = $(USER)

# Compiler selection
CXX = g++
CC = gcc

# C++ Compiler configuration
# Warning flags for comprehensive error checking
CXX_WARNINGS = -Wall -Weffc++ -Wextra -Wsign-conversion -pedantic-errors \
               -Wcast-align -Wcast-qual -Wctor-dtor-privacy -Wdisabled-optimization \
               -Wlogical-op -Wmissing-declarations -Wnoexcept -Wnon-virtual-dtor \
               -Wold-style-cast -Woverloaded-virtual -Wredundant-decls -Wshadow \
               -Wsign-promo -Wstrict-null-sentinel -Wstrict-overflow=5 -Wundef

# Debug flags optimized for research and development
CXX_DEBUG = -ggdb3 -fno-omit-frame-pointer -fno-inline-functions-called-once \
            -fno-optimize-sibling-calls

# Optimization for research
CXX_OPTIMIZE = -O2

# Language standard
CXX_STANDARD = -std=c++17

# Combined C++ flags
CXX_FLAGS = $(CXX_WARNINGS) $(CXX_DEBUG) $(CXX_OPTIMIZE) $(CXX_STANDARD)

# C Compiler configuration
# Warning flags for C code
C_WARNINGS = -Wall -Wextra -Wpedantic -Wformat=2 -Wcast-align -Wcast-qual \
             -Wdisabled-optimization -Winit-self -Wlogical-op -Wmissing-declarations \
             -Wmissing-include-dirs -Wredundant-decls -Wshadow -Wstrict-overflow=5 \
             -Wundef -Wwrite-strings -Wpointer-arith

# Debug flags for C code
C_DEBUG = -ggdb3 -fno-omit-frame-pointer -fno-inline-functions-called-once

# Optimization for C code (research-focused)
C_OPTIMIZE = -O2

# Language standard for C
C_STANDARD = -std=c11

# Combined C flags
C_FLAGS = $(C_WARNINGS) $(C_DEBUG) $(C_OPTIMIZE) $(C_STANDARD)

# Research-specific compilation options
# Enable additional debugging features useful for cryptographic research
RESEARCH_FLAGS = -DRESEARCH_BUILD -DENABLE_DETAILED_LOGGING -DENABLE_TIMING_ANALYSIS

# Memory debugging options (can be enabled for specific builds)
MEMORY_DEBUG_FLAGS = -fsanitize=address -fsanitize=undefined -fstack-protector-strong

# Profiling support
PROFILING_FLAGS = -pg -fno-omit-frame-pointer

# Coverage analysis support
COVERAGE_FLAGS = --coverage -fprofile-arcs -ftest-coverage

# Default build type for research (debug-oriented)
BUILD_TYPE ?= debug

# Static library creation flags
AR_FLAGS = rcs

# Archiver tool
AR = ar

# Additional research tools
VALGRIND = valgrind
VALGRIND_FLAGS = --leak-check=full --show-leak-kinds=all --track-origins=yes --verbose

# Code analysis tools
CPPCHECK = cppcheck
CPPCHECK_FLAGS = --enable=all --std=c++17 --verbose --check-config

