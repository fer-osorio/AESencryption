# command-line-tools/Makefile
include ../common.mk
include ../config.mk

# Local configuration
MODULE_NAME = $(notdir $(CURDIR))
PROJECT_ROOT := $(call find-project-root)
MODULE_DIRECTORIES := $(shell find . -mindepth 1 -type d -print0 | xargs -0 -n 1 basename)

# Binaries and objects directories
BINDIR = $(PROJECT_ROOT)/bin/$(MODULE_NAME)
OBJDIR = $(PROJECT_ROOT)/obj/$(MODULE_NAME)

# Local includes
# Local includes and libraries
INCLUDES = \
    -I$(PROJECT_ROOT)/crypto-cli/include \
    -I$(PROJECT_ROOT)/file-handlers/include \
    -I$(PROJECT_ROOT)/include \
    -I$(PROJECT_ROOT)/data-encryption/include \
    -I$(PROJECT_ROOT)/metrics-analysis/include

LDFLAGS += -L$(PROJECT_ROOT)/lib
LIBS = -lcryptocli -lfilehandlers -laesencryption_cpp  -laesencryption_c  -lmetricsanalysis

# Define required dependencies (library files)
REQUIRED_DEPS = \
    $(PROJECT_ROOT)/lib/libaesencryption_c.a \
    $(PROJECT_ROOT)/lib/libaesencryption_cpp.a \
    $(PROJECT_ROOT)/lib/libfilehandlers.a \
    $(PROJECT_ROOT)/lib/libmetricsanalysis.a \
    $(PROJECT_ROOT)/lib/libcryptocli.a

# Source files
SOURCES = $(call find_local_sources,cpp)
# Object files
OBJECTS = $(foreach md,$(MODULE_DIRECTORIES), \
        $(call sources_to_objects,$(filter $(md)/%,$(SOURCES)),$(OBJDIR)/$(md),cpp) \
)
# Binary files
BINARIES = $(patsubst $(OBJDIR)/%.o,$(BINDIR)/%,$(OBJECTS))

# Default target
all: check-deps $(BINARIES)

# Check dependencies
check-deps:
	$(call check_dependencies)

# Build dependencies (optional - for convenience)
dependencies:
	$(call print_info,"Building project dependencies...")
	@$(MAKE) -C $(PROJECT_ROOT)/data-encryption
	@$(MAKE) -C $(PROJECT_ROOT)/src
	@$(MAKE) -C $(PROJECT_ROOT)/file-handlers
	@$(MAKE) -C $(PROJECT_ROOT)/metrics-analysis
	@$(MAKE) -C $(PROJECT_ROOT)/crypto-cli
	$(call print_success,"All dependencies built successfully")


# Build executables
$(BINDIR)/%: $(OBJDIR)/%.o | $(BINDIR) $(OBJDIR)
	@mkdir -p $(dir $@)
	$(call create_executable,$@,$^,)

# Compilation rule for C++ files
$(OBJDIR)/%.o: %.cpp | $(OBJDIR)
	@mkdir -p $(dir $@)
	$(call compile_cpp_rule,$<,$@,$(INCLUDES))

# Directory creation
$(OBJDIR) $(BINDIR):
	$(call create_dir,$@)

# Clean target
clean:
	$(call clean_standard)
	@rm -f $(BINARIES)
	$(call print_success,"Cleaned command-line-tools module")

.PHONY: clean

# Dependency inclusion
$(eval $(include_deps))
