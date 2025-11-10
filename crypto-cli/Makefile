# CLI/Makefile
include ../common.mk
include ../config.mk

# Local configuration
MODULE_NAME = $(notdir $(CURDIR))
PROJECT_ROOT := $(call find-project-root)
LIBDIR = $(PROJECT_ROOT)/lib
TARGET_LIB = $(LIBDIR)/libcryptocli.a

# Local source directory and object directory
SRCDIR = src
OBJDIR = $(PROJECT_ROOT)/obj/$(notdir $(CURDIR))

# Source files
SOURCES = $(wildcard $(SRCDIR)/*.cpp)
OBJECTS = $(SOURCES:$(SRCDIR)/%.cpp=$(OBJDIR)/%.o)

# Local includes (in addition to common includes)
INCDIR = include
INCLUDES = -I./$(INCDIR) -I$(PROJECT_ROOT)/$(INCDIR)

# Dependencies on other modules
DEPS =$(LIBDIR)/libaesencryption_cpp.a

# External libraries needed
LIBS = -L$(LIBDIR) -laesencryption_cpp

# Default target
all: $(TARGET_LIB)

# Check dependencies
check-deps:
	@missing_deps=""; \
	for dep in $(DEPS); do \
		if [ ! -f "$$dep" ]; then \
			missing_deps="$$missing_deps $$dep"; \
		fi; \
	done; \
	if [ -n "$$missing_deps" ]; then \
		$(call print_error,"Missing dependencies:$$missing_deps"); \
		$(call print_info,"Build required modules first:"); \
		$(call print_info,"  make -C ../src"); \
		exit 1; \
	fi

# Library target
$(TARGET_LIB): check-deps $(OBJECTS) | $(LIBDIR) $(OBJDIR)
	$(call create_static_lib,$@,$(OBJECTS))

# Compilation rule for C++ files
$(OBJDIR)/%.o: $(SRCDIR)/%.cpp | $(OBJDIR)
	$(call compile_cpp_rule,$<,$@,$(INCLUDES))

# Directory creation
$(OBJDIR) $(LIBDIR):
	$(call create_dir,$@)

# Clean target
clean:
	$(call clean_standard)
	@rm -f $(TARGET_LIB)
	$(call print_success,"Cleaned CLI module")

# Dependency inclusion
$(eval $(include_deps))

# Module-specific targets
.PHONY: check-deps setup-test-data
