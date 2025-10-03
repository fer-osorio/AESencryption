# src/Makefile - Main C++ implementation
include ../common.mk
include ../config.mk

# Local configuration
MODULE_NAME = src
PROJECT_ROOT := $(call find-project-root)
LIBDIR = $(PROJECT_ROOT)/lib
TARGET_LIB = $(LIBDIR)/libaesencryption_cpp.a

# Local source directory and object directory
SRCDIR = core
OBJDIR = $(PROJECT_ROOT)/obj/$(notdir $(CURDIR))

# Local includes
INCLUDES = -I./utils/ -I$(PROJECT_ROOT)/data-encryption/include -I$(PROJECT_ROOT)/include

# Source files
SOURCES = $(call find_sources,$(SRCDIR),cpp)
#$(info SOURCES=$(SOURCES))
# Object files
OBJECTS = $(call sources_to_objects,$(SOURCES),$(OBJDIR),cpp)
#$(info OBJECTS=$(OBJECTS))

# Dependencies on other modules
DEPS = $(LIBDIR)/libaesencryption_c.a

# External libraries needed
LIBS = -laesencryption_c

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

$(OBJDIR)/%.o: $(SRCDIR)/%.cpp | $(OBJDIR)
	$(call compile_cpp_rule,$<,$@,$(INCLUDES))

# Directory creation
$(OBJDIR) $(LIBDIR):
	$(call create_dir,$@)

# Clean target
clean:
	$(call clean_dir,$(OBJDIR))
	@rm -f $(TARGET_LIB)
	$(call print_success,"Cleaned core C++ module: $(MODULE_NAME)")

# Debug symbols check
check-symbols: $(TARGET_LIB)
	$(call print_info,"Checking symbols in $(TARGET_LIB):")
	@nm $(TARGET_LIB) | grep -E "(T|t)" | head -20

# Dependency inclusion
$(eval $(include_deps))
