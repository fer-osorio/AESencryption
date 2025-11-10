# data-encryption/Makefile - Pure C AES implementation
include ../common.mk
include ../config.mk

# Module configuration
MODULE_NAME = $(notdir $(CURDIR))
PROJECT_ROOT := $(call find-project-root)
LIBDIR = $(PROJECT_ROOT)/lib
TARGET_LIB = $(LIBDIR)/libaesencryption_c.a

# Local source directory and object directory
SRCDIR = src
OBJDIR = $(PROJECT_ROOT)/obj/data-encryption

# Local includes (private headers)
INCDIR = include
INCLUDES = -I$(INCDIR)

# Source files and objects
SOURCES = $(wildcard $(SRCDIR)/*.c)
OBJECTS = $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

# Default target
all: $(TARGET_LIB)

# Static library creation
$(TARGET_LIB): $(OBJECTS) | $(OBJDIR) $(LIBDIR)
	$(call create_static_lib,$@,$(OBJECTS))

# Compilation rule for C files
$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(call compile_c_rule,$<,$@,$(INCLUDES))

# Directory creation
$(OBJDIR) $(LIBDIR):
	$(call create_dir,$@)

# Clean target
clean:
	$(call clean_standard)
	@rm -f $(TARGET_LIB)
	$(call print_success,"Cleaned $(MODULE_NAME) module")

# Static analysis of C code
analyze: $(TARGET_LIB)
	$(call print_info,"Running static analysis on C code...")
	@if command -v $(CPPCHECK) >/dev/null 2>&1; then \
		$(CPPCHECK) $(CPPCHECK_FLAGS) --language=c $(SRCDIR)/; \
		$(call print_success,"Static analysis completed"); \
	else \
		$(call print_warning,"$(CPPCHECK) not found, skipping analysis"); \
	fi

# Show library information
info: $(TARGET_LIB)
	$(call print_info,"Library information for $(TARGET_LIB):")
	@file $(TARGET_LIB)
	@echo "Symbols:"
	@nm $(TARGET_LIB) | grep -E "(T|t)" | head -10

# Dependency inclusion
$(eval $(include_deps))

# Additional phony targets
.PHONY: test analyze test-memory info
