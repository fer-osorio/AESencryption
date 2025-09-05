# src/Makefile - Main C++ implementation
include ../common.mk

# Local configuration
LIBDIR = $(PROJECT_ROOT)/lib
OBJDIR = $(PROJECT_ROOT)/obj/$(notdir $(CURDIR))
BINDIR = $(PROJECT_ROOT)/bin
TARGET_LIB = $(LIBDIR)/libaesencryption_cpp.a

# Project root
PROJECT_ROOT := $(call find-project-root)

# Source files
SOURCES = $(wildcard $(SRCDIR)/*.cpp)

# Object files
OBJECTS = $(SOURCES:$(SRCDIR)/%.cpp=$(OBJDIR)/%.o)

# Local includes (in addition to common includes)
INCLUDES = -I$(INCDIR)

# Dependencies on other modules
DEPS = $(LIBDIR)/libaesencryption_c.a

# External libraries needed
LIBS = -L$(LIBDIR) -laesencryption_c

# Default target
all: $(TARGET_LIB)

# Check dependencies
check-deps:
	@if [ ! -f "$(LIBDIR)/libaesencryption_c.a" ]; then \
		$(call print_error,"Dependency libaesencryption_c.a not found. Build data-encryption first."); \
		$(call print_info,"Run: make -C ../data-encryption"); \
		exit 1; \
	fi

# Library target
$(TARGET_LIB): check-deps $(OBJECTS) | $(LIBDIR)
	$(call create_static_lib,$@,$(OBJECTS))

# Compilation rule for C++ files
$(eval $(compile_cxx_rule))

# Directory creation
$(OBJDIR) $(LIBDIR):
	$(call create_dir,$@)

# Clean target
clean:
	$(call clean_standard)
	@rm -f $(TARGET_LIB)
	$(call print_success,"Cleaned core C++ module")

# Test target
test: BUILD_TYPE=test
test: $(TARGET_LIB)
	$(call print_info,"Running core C++ tests...")
	# Compile and run unit tests for key.cpp, cipher.cpp, encryptor.cpp
	@if [ -d "../tests/unit" ]; then \
		$(MAKE) -C ../tests unit-core; \
	else \
		$(call print_warning,"No unit tests found for core module"); \
	fi

# Integration test with C library
test-integration: $(TARGET_LIB)
	$(call print_info,"Running C/C++ integration tests...")
	@$(CXX) $(CXXFLAGS) $(CXX_STD) $(COMMON_INCLUDES) \
		-o $(BINDIR)/test_integration \
		test_integration.cpp \
		$(LDFLAGS) $(LIBS) -laesencryption_cpp
	@$(BINDIR)/test_integration
	$(call print_success,"Integration tests passed")

# Debug symbols check
check-symbols: $(TARGET_LIB)
	$(call print_info,"Checking symbols in $(TARGET_LIB):")
	@nm $(TARGET_LIB) | grep -E "(T|t)" | head -20

# Dependency inclusion
$(eval $(include_deps))
