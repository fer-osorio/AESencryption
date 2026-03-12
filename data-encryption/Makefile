# data-encryption/Makefile - Pure C AES implementation
include ../common.mk
include ../config.mk

# Module configuration
MODULE_NAME = $(notdir $(CURDIR))
PROJECT_ROOT := $(call find-project-root)
LIBDIR = $(PROJECT_ROOT)/lib
TARGET_LIB = $(LIBDIR)/libaesencryption_c.a

# Local source directory and object directory
OBJDIR = $(PROJECT_ROOT)/obj/$(notdir $(CURDIR))

# Local includes (private headers)
INCLUDES = -I$(PROJECT_ROOT)/data-encryption/$(INCDIR)

# Source files and objects
SOURCES = $(wildcard $(SRCDIR)/*.c)
OBJECTS = $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

# Static analysis with cppcheck
CPPCHECK = cppcheck
CPPCHECK_FLAGS = --check-level=exhaustive

# Default target
all: $(TARGET_LIB)

# Static library creation
$(TARGET_LIB): $(OBJECTS) | $(LIBDIR) $(OBJDIR)
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
		echo -e "$(COLOR_GREEN)[SUCCESS]$(COLOR_NC) Static analysis completed"; \
	else \
		echo -e "$(COLOR_YELLOW)[WARNING]$(COLOR_NC) $(CPPCHECK) not found - skipping analysis"; \
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
.PHONY: all clean analyze info
