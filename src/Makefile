# src/Makefile - Main C++ implementation
include ../common.mk
include ../config.mk

# Local configuration
MODULE_NAME = src
PROJECT_ROOT := $(call find-project-root)
LIBDIR = $(PROJECT_ROOT)/lib
TARGET_LIB = $(LIBDIR)/libaesencryption_cpp.a

# Local source directory and object directory
CORE = ./core
UTILS  = ./utils
OBJDIR = $(PROJECT_ROOT)/obj/$(notdir $(CURDIR))

# Local includes
INCLUDES = -I./utils/include -I$(PROJECT_ROOT)/data-encryption/include -I$(PROJECT_ROOT)/include

# Source files
SOURCES = $(wildcard $(CORE)/*.cpp) $(wildcard $(UTILS)/*.cpp)
# Object files
OBJECTS = $(SOURCES:$(CORE)/%.cpp=$(OBJDIR)/%.o)

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
$(TARGET_LIB): check-deps $(OBJECTS) | $(OBJDIR) $(LIBDIR)
	$(call create_static_lib,$@,$(OBJECTS))

$(OBJDIR)/$(CORE)/%.o: $(CORE)/%.cpp | $(OBJDIR)
	$(call compile_cpp_rule,$<,$@,$(INCLUDES))

$(OBJDIR)/$(UTILS)/%.o: $(UTILS)/%.cpp | $(OBJDIR)
	$(call compile_cpp_rule,$<,$@,$(INCLUDES))

# Directory creation
$(OBJDIR)/$(CORE) $(OBJDIR)/$(UTILS) $(LIBDIR):
	$(call create_dir,$@)

# Clean target
clean:
	$(call clean_standard)
	@rm -f $(TARGET_LIB)
	$(call print_success,"Cleaned core C++ module: $(MODULE_NAME)")

# Debug symbols check
check-symbols: $(TARGET_LIB)
	$(call print_info,"Checking symbols in $(TARGET_LIB):")
	@nm $(TARGET_LIB) | grep -E "(T|t)" | head -20

# Dependency inclusion
$(eval $(include_deps))
