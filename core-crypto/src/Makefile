# src/Makefile - Main C++ implementation
include ../../common.mk
include ../../config.mk

# Local configuration
MODULE_NAME = core
PROJECT_ROOT := $(call find-project-root)
LIBDIR = $(PROJECT_ROOT)/lib
TARGET_LIB = $(LIBDIR)/libaesencryption_cpp.a

# Local source directory and object directory
SRCDIR = core
OBJDIR = $(PROJECT_ROOT)/obj/$(notdir $(CURDIR))

# Local includes
INCLUDES = -I./utils/ -I$(PROJECT_ROOT)/core-crypto/aes/include -I$(PROJECT_ROOT)/core-crypto/include

# Source files
SOURCES = $(wildcard $(SRCDIR)/*.cpp)
OBJECTS = $(SOURCES:$(SRCDIR)/%.cpp=$(OBJDIR)/%.o)

# Dependencies on other modules
DEPS = $(LIBDIR)/libaesencryption_c.a

# External libraries needed
LIBS = -laesencryption_c

# Default target
all: $(TARGET_LIB)

# Check dependencies
check-deps:
	$(call check_dependencies)

dependencies:
	$(call print_info,"Building project dependencies...")
	@$(MAKE) -C $(PROJECT_ROOT)/core-crypto/aes
	$(call print_success,"All dependencies built successfully")

# Library target
$(TARGET_LIB): check-deps $(OBJECTS) | $(LIBDIR) $(OBJDIR)
	$(call create_static_lib,$@,$(OBJECTS))

$(OBJDIR)/%.o: $(SRCDIR)/%.cpp | $(OBJDIR)
	$(call compile_cpp_rule,$<,$@,$(INCLUDES))

# Directory creation
$(OBJDIR) $(LIBDIR):
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

.PHONY: all clean check-deps dependencies check-symbols
