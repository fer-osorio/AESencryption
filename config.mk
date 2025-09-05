# config.mk - Project-wide configuration
# This file contains compiler settings and project-specific configurations
# Include this file in common.mk and other Makefiles that need these settings

# Project information
PROJECT_NAME = aes-encryption
AUTHOR = $(USER)

# Compiler selection
CXX = g++
CC = gcc

# Compiler configuration
# Base flags
BASE_CFLAGS = -Wall -Wextra -Wpedantic -Wformat=2 -Wcast-align -Wcast-qual \
              -Wdisabled-optimization -Winit-self -Wlogical-op -Wmissing-declarations \
              -Wmissing-include-dirs -Wredundant-decls -Wshadow -Wstrict-overflow=5 \
              -Wundef -Wno-unused -Wno-variadic-macros -Wno-parentheses -fdiagnostics-show-option

BASE_CXXFLAGS = $(BASE_CFLAGS) -Wctor-dtor-privacy -Wnoexcept -Wnon-virtual-dtor \
                -Wstrict-null-sentinel -Wold-style-cast -Woverloaded-virtual -Wsign-promo

# Language standard
CXX_STANDARD = -std=c++17

# Language standard for C
C_STANDARD = -std=c11

# Memory debugging options (can be enabled for specific builds)
MEMORY_DEBUG_FLAGS = -fsanitize=address -fsanitize=leak -fsanitize=undefined -fstack-protector-strong

# Debug flags
DEBUG = -ggdb3 $(MEMORY_DEBUG_FLAGS) -fno-omit-frame-pointer -fno-inline-functions-called-once

# Profiling support
PROFILING_FLAGS = -pg -fno-omit-frame-pointer

# Optimization
NO_OPTIMIZE = -O0
OPTIMIZE = -O2

# Coverage analysis support
COVERAGE_FLAGS = --coverage -fprofile-arcs -ftest-coverage

# Default build type (debug-oriented)
BUILD_TYPE ?= debug

# Build type specific flags
ifeq ($(BUILD_TYPE),debug)
    CFLAGS   = $(BASE_CFLAGS) $(DEBUG) $(NO_OPTIMIZE)
    CXXFLAGS = $(BASE_CXXFLAGS) $(DEBUG) $(NO_OPTIMIZE)
    LDFLAGS  = $(MEMORY_DEBUG_FLAGS)
else ifeq ($(BUILD_TYPE),test)
    CFLAGS = $(BASE_CFLAGS) -g $(NO_OPTIMIZE) $(COVERAGE_FLAGS)
    CXXFLAGS = $(BASE_CXXFLAGS) -g $(NO_OPTIMIZE) $(COVERAGE_FLAGS)
    LDFLAGS = $(COVERAGE_FLAGS)
else ifeq ($(BUILD_TYPE),profile)
    CFLAGS = $(BASE_CFLAGS) -g $(OPTIMIZE) $(PROFILING_FLAGS)
    CXXFLAGS = $(BASE_CXXFLAGS) -g $(OPTIMIZE) $(PROFILING_FLAGS)
    LDFLAGS = $(PROFILING_FLAGS)

# Library flags
STATIC_LIB_FLAGS = rcs
SHARED_LIB_FLAGS = -shared -fPIC

