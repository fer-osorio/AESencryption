# test-framework/Makefile - NIST AES test vectors library
include ../common.mk
BUILD_TYPE ?= test
include ../config.mk

# Module configuration
MODULE_NAME = $(notdir $(CURDIR))
PROJECT_ROOT := $(call find-project-root)
LIBDIR = $(PROJECT_ROOT)/lib
TARGET_LIB = $(LIBDIR)/libtest_vectors.a

# Local source directory and object directory
OBJDIR = $(PROJECT_ROOT)/obj/$(notdir $(CURDIR))

# Local includes (private headers)
INCLUDES = -I$(PROJECT_ROOT)/test-framework/$(INCDIR) -I$(PROJECT_ROOT)/test-framework/$(INCDIR)/test-vectors

# Source files and objects
SOURCES = $(wildcard $(SRCDIR)/test-vectors/*.cpp)
OBJECTS = $(call sources_to_objects,$(SOURCES),$(OBJDIR),cpp)

# Default target
all: $(TARGET_LIB)

# Static library creation
$(TARGET_LIB): $(OBJECTS) | $(LIBDIR) $(OBJDIR)
	$(call create_static_lib,$@,$(OBJECTS))

# Compilation rule for C++ files
$(OBJDIR)/%.o: $(SRCDIR)/test-vectors/%.cpp | $(OBJDIR)
	$(call compile_cpp_rule,$<,$@)

# Directory creation
$(OBJDIR) $(LIBDIR):
	$(call create_dir,$@)

# Clean target
clean:
	$(call clean_standard)
	@rm -f $(TARGET_LIB)
	$(call print_success,"Cleaned $(MODULE_NAME) module")

# Dependency inclusion
$(eval $(include_deps))

.PHONY: all clean
