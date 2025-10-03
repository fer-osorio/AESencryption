# common.mk - Shared Makefile rules and functions
# Include this file in other Makefiles with: include $(PROJECT_ROOT)/common.mk

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
    fi)
endef

# Color codes for output
COLOR_RED     = \e[31m
COLOR_GREEN   = \e[32m
COLOR_YELLOW  = \e[33m
COLOR_BLUE    = \e[34m
COLOR_PURPLE  = \e[35m
COLOR_CYAN    = \e[36m
COLOR_NC      = \e[0m # No Color

# Standard directories
SRCDIR ?= src
INCDIR ?= include

# Common include paths
COMMON_INCLUDES = -I$(PROJECT_ROOT)/include \
                  -I$(PROJECT_ROOT)/data-encryption/include \
                  -I$(PROJECT_ROOT)/file-handlers/include \
                  -I$(PROJECT_ROOT)/metrics-analysis/include

# Utility functions
define print_success
	@echo -e "$(COLOR_GREEN)[SUCCESS]$(COLOR_NC) $(1)"
endef

define print_error
	@echo -e "$(COLOR_RED)[ERROR]$(COLOR_NC) $(1)"
endef

define print_warning
	@echo -e "$(COLOR_YELLOW)[WARNING]$(COLOR_NC) $(1)"
endef

define print_info
	@echo -e "$(COLOR_BLUE)[INFO]$(COLOR_NC) $(1)"
endef

define print_building
	@echo -e "$(COLOR_CYAN)[BUILDING]$(COLOR_NC) $(1)"
endef

# Intended for bash
define echo_success
	echo -e "$(COLOR_GREEN)[SUCCESS]$(COLOR_NC) $(1)"
endef

define echo_error
	echo -e "$(COLOR_RED)[ERROR]$(COLOR_NC) $(1)"
endef

define echo_warning
	echo -e "$(COLOR_YELLOW)[WARNING]$(COLOR_NC) $(1)"
endef

define echo_info
	echo -e "$(COLOR_BLUE)[INFO]$(COLOR_NC) $(1)"
endef

define echo_building
	echo -e "$(COLOR_CYAN)[BUILDING]$(COLOR_NC) $(1)"
endef


# Directory creation function
define create_dir
$(shell \
    if [ ! -d $(1) ]; then \
        mkdir --parents $(1); \
        echo -e "$(COLOR_BLUE)[INFO]$(COLOR_NC) Created directory: $(1)" >&2; \
    fi)
endef

# Generic compilation rules
define compile_c_rule
	$(call print_building,"C object:\\n\\t\\t$(2)")
	$(call create_dir,$(dir $(2)))
	@$(CC) $(CFLAGS) $(C_STANDARD) $(INCLUDES)  -MMD -MP -c $(1) -o $(2)
	$(call print_success,"Compiled:\\n\\t\\t$(2)")
endef

# Standard compilation rule for cpp files
# Usage: $(call compile_cpp_rule,source_file,object_file,additional_flags)
define compile_cpp_rule
	$(call print_building,"C++ object:\\n\\t\\t$(2)")
	$(call create_dir,$(dir $(2)))
	@$(CXX) $(CXXFLAGS) $(CXX_STANDARD) $(INCLUDES) $(3) -MMD -MP -c $(1) -o $(2)
	$(call print_success,"Compiled:\\n\\t\\t$(2)")
endef

# Static library creation
define create_static_lib
	$(call print_building,"Static library:\\n\\t\\t$(1)")
	@ar $(STATIC_LIB_FLAGS) $(1) $(2)
	@ranlib $(1)
	$(call print_success,"Created static library:\\n\\t\\t$(1)")
endef

# Shared library creation
define create_shared_lib
	$(call print_building,"Shared library:\\n\\t\\t$(1)")
	@$(CXX) $(SHARED_LIB_FLAGS) -o $(1) $(2) $(LDFLAGS) $(LIBS)
	$(call print_success,"Created shared library:\\n\\t\\t$(1)")
endef

# Executable creation
# Usage: $(call create_executable,executable,objects)
define create_executable
	$(call print_building,"Executable:\\n\\t\\t$(1)")
	@$(CXX) $(2) -o $(1) $(LDFLAGS) $(LIBS)
	$(call print_success,"Created executable:\\n\\t\\t$(1)")
endef

# Function to find all source files in local directory
# Usage: $(call find_local_sources,extension)
define find_local_sources
$(or $(patsubst ./%,%,$(shell find . -name "*.$(1)" 2>/dev/null)),$(warning No $(1) files found))
endef

# Function to find all source files in specified directory
# Usage: $(call find_sources,directory,extension)
define find_sources
$(or $(patsubst ./%,%,$(shell find $(1) -name "*.$(2)" 2>/dev/null)),$(warning No $(2) files found in $(1)))
endef

# Function to convert source files to object files
# Usage: OBJECTS = $(call sources_to_objects,sources,destination_dir,extension)
# If $(1) has .cpp as suffix, the suffix gets "cutted" and the $(2)/obj/>>the rest of $(1)<<.o is the output
define sources_to_objects
$(patsubst %.$(3),$(2)/%.o,$(notdir $(1)))
endef

# Clean function. Standard setting
define clean_standard
	$(call print_info,"Cleaning $(OBJDIR)")
	@rm -rf $(OBJDIR)
	$(call print_info,"Cleaning dependency files")
	@find . -name "*.d" -delete 2>/dev/null || true
endef

# Clean directory function. Non-standar setting
# Usage: $(call clean_dir,directory_path)
define clean_dir
	$(call print_info,"Cleaning $(1)")
	@rm -rf $(1)
endef

# Clean dependency files from directory
# Usage: $(call clean_deps,directory_path)
define clean_deps
	$(call print_info,"Cleaning dependency files")
	@find $(1) -name "*.d" -delete 2>/dev/null || true
endef

# Dependency inclusion (include at end of Makefile)
define include_deps
-include $(OBJECTS:.o=.d)
endef

# Help function - shows available targets
# Usage: $(call show_help)
define show_help
	@echo -e "$(COLOR_BLUE)Available targets:$(COLOR_NC)"
	@echo -e "  all     - Build everything (default: debug mode)"
	@echo -e "  debug   - Build with debug flags"
	@echo -e "  test    - Build with test coverage flags"
	@echo -e "  profile - Build with profiling flags"
	@echo -e "  clean   - Clean build artifacts"
	@echo -e "  help    - Show this help"
	@echo -e ""
	@echo -e "$(COLOR_BLUE)Build types:$(COLOR_NC)"
	@echo -e "  make BUILD_TYPE=debug"
	@echo -e "  make BUILD_TYPE=test"
	@echo -e "  make BUILD_TYPE=profile"
endef

# Default target selection based on build type
debug: BUILD_TYPE=debug
debug: all

test: BUILD_TYPE=test
test: all

profile: BUILD_TYPE=profile
profile: all

# Standard phony targets
.PHONY: all clean debug help
