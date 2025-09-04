# common.mk - Shared Makefile rules and functions
# Include this file in other Makefiles with: include ../common.mk
include config.mk

# Project root detection
# Usage: PROJECT_ROOT := $(call find-project-root)
define find-project-root
$(shell \
    start_dir=$$(pwd); \
    while [ ! -f .git/config ] && [ ! -f common.mk ] && [ "$$(pwd)" != "/" ]; do cd ..; done; \
    if [ ! -f .git/config ] || [ ! -f common.mk ] ; then \
        echo "ERROR: Could not find project root from $$start_dir" >&2; \
        echo "/tmp"; \
    else \
        pwd; \
endef

# Color codes for output
COLOR_RED     = \033[0;31m
COLOR_GREEN   = \033[0;32m
COLOR_YELLOW  = \033[0;33m
COLOR_BLUE    = \033[0;34m
COLOR_PURPLE  = \033[0;35m
COLOR_CYAN    = \033[0;36m
COLOR_NC      = \033[0m # No Color

# Standard directories
SRCDIR ?= src
INCDIR ?= include
OBJDIR ?= $(PROJECT_ROOT)/obj/$(notdir $(CURDIR))
LIBDIR ?= $(PROJECT_ROOT)/lib
BINDIR ?= $(PROJECT_ROOT)/bin

# Common include paths
COMMON_INCLUDES = -I$(PROJECT_ROOT)/include \
                  -I$(PROJECT_ROOT)/data-encryption/include \
                  -I$(PROJECT_ROOT)/file-handlers/include \
                  -I$(PROJECT_ROOT)/metrics-analysis/include

# Utility functions
define print_success
	@printf "$(COLOR_GREEN)[SUCCESS]$(COLOR_NC) %s\n" "$(1)"
endef

define print_error
	@printf "$(COLOR_RED)[ERROR]$(COLOR_NC) %s\n" "$(1)"
endef

define print_warning
	@printf "$(COLOR_YELLOW)[WARNING]$(COLOR_NC) %s\n" "$(1)"
endef

define print_info
	@printf "$(COLOR_BLUE)[INFO]$(COLOR_NC) %s\n" "$(1)"
endef

define print_building
	@printf "$(COLOR_CYAN)[BUILDING]$(COLOR_NC) %s\n" "$(1)"
endef

# Directory creation function
define create_dir
	@mkdir -p $(1)
	$(call print_info,"Created directory: $(1)")
endef

# Dependency generation for C files
define make_c_depend
	@$(CC) $(CFLAGS) $(COMMON_INCLUDES) $(INCLUDES) -MM -MT $@ -MF $(patsubst %.o,%.d,$@) $<
endef

# Dependency generation for C++ files
define make_cxx_depend
	@$(CXX) $(CXXFLAGS) $(COMMON_INCLUDES) $(INCLUDES) -MM -MT $@ -MF $(patsubst %.o,%.d,$@) $<
endef

# Generic compilation rules
define compile_c_rule
$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(call make_c_depend)
	$(call print_building,"C object: $$@")
	@$(CC) $(CFLAGS) $(C_STANDARD) $(COMMON_INCLUDES) $(INCLUDES) -c $$< -o $$@
	$(call print_success,"Compiled: $$@")
endef

define compile_cxx_rule
$(OBJDIR)/%.o: $(SRCDIR)/%.cpp | $(OBJDIR)
	$(call make_cxx_depend)
	$(call print_building,"C++ object: $$@")
	@$(CXX) $(CXXFLAGS) $(CXX_STANDARD) $(COMMON_INCLUDES) $(INCLUDES) -c $$< -o $$@
	$(call print_success,"Compiled: $$@")
endef

# Static library creation
define create_static_lib
	$(call print_building,"Static library: $(1)")
	@ar $(STATIC_LIB_FLAGS) $(1) $(2)
	@ranlib $(1)
	$(call print_success,"Created static library: $(1)")
endef

# Shared library creation
define create_shared_lib
	$(call print_building,"Shared library: $(1)")
	@$(CXX) $(SHARED_LIB_FLAGS) -o $(1) $(2) $(LDFLAGS) $(LIBS)
	$(call print_success,"Created shared library: $(1)")
endef

# Executable creation
define create_executable
	$(call print_building,"Executable: $(1)")
	@$(CXX) -o $(1) $(2) $(LDFLAGS) $(LIBS)
	$(call print_success,"Created executable: $(1)")
endef

# Clean function
define clean_standard
	$(call print_info,"Cleaning $(OBJDIR)")
	@rm -rf $(OBJDIR)
	$(call print_info,"Cleaning dependency files")
	@find . -name "*.d" -delete 2>/dev/null || true
endef

# Dependency inclusion (include at end of Makefile)
define include_deps
-include $(OBJECTS:.o=.d)
endef

# Standard phony targets
.PHONY: all clean debug test profile help

# Help target
help:
	@echo "$(COLOR_BLUE)Available targets:$(COLOR_NC)"
	@echo "  all     - Build everything (default: debug mode)"
	@echo "  debug   - Build with debug flags"
	@echo "  test    - Build with test coverage flags"
	@echo "  profile - Build with profiling flags"
	@echo "  clean   - Clean build artifacts"
	@echo "  help    - Show this help"
	@echo ""
	@echo "$(COLOR_BLUE)Build types:$(COLOR_NC)"
	@echo "  make BUILD_TYPE=debug"
	@echo "  make BUILD_TYPE=test"
	@echo "  make BUILD_TYPE=profile"

# Default target selection based on build type
debug: BUILD_TYPE=debug
debug: all

test: BUILD_TYPE=test
test: all

profile: BUILD_TYPE=profile
profile: all
