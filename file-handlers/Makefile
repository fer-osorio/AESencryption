# file-handlers/Makefile
include ../common.mk
include ../config.mk

# Local configuration
MODULE_NAME = $(notdir $(CURDIR))
PROJECT_ROOT := $(call find-project-root)
LIBDIR = $(PROJECT_ROOT)/lib
TARGET_LIB = $(LIBDIR)/libfilehandlers.a

# Local source directory and object directory
OBJDIR = $(PROJECT_ROOT)/obj/$(notdir $(CURDIR))

# Source files
SOURCES = $(wildcard $(SRCDIR)/*.cpp)
OBJECTS = $(SOURCES:$(SRCDIR)/%.cpp=$(OBJDIR)/%.o)

# Local includes (in addition to common includes)
INCLUDES = -I./$(INCDIR) -I../$(INCDIR) -I../metrics-analysis/$(INCDIR)

# Dependencies on other modules
DEPS = $(LIBDIR)/libaesencryption_cpp.a $(LIBDIR)/libmetricsanalysis.a

# External libraries needed
LIBS = -L$(LIBDIR) -laesencryption_cpp lmetricsanalysis

# Default target
all: $(TARGET_LIB)

# Check dependencies
check-deps:
	$(call check_dependencies)

# Build dependencies (optional - for convenience)
dependencies:
	$(call print_info,"Building project dependencies...")
	@$(MAKE) -C $(PROJECT_ROOT)/src
	@$(MAKE) -C $(PROJECT_ROOT)/metrics-analysis
	$(call print_success,"All dependencies built successfully")

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
	$(call print_success,"Cleaned file-handlers module")

# Create test data structure
setup-test-data:
	$(call print_info,"Setting up test data structure...")
	@mkdir -p ../data/{text,images,binary,test_output}
	@echo "This is a sample text file for encryption testing." > ../data/text/sample.txt
	@echo "Another sample with different content for variety." > ../data/text/sample2.txt
	$(call print_success,"Test data structure created")

# Dependency inclusion
$(eval $(include_deps))

# Module-specific targets
.PHONY: check-deps setup-test-data

# List supported file formats
list-formats:
	@echo "$(COLOR_BLUE)Supported file formats:$(COLOR_NC)"
	@echo "  - Text files (.txt)"
	@echo "  - Bitmap images (.bmp)"
	@echo "  - Binary files (generic)"
	@echo "$(COLOR_YELLOW)Planned formats:$(COLOR_NC)"
	@echo "  - PNG images"
	@echo "  - JPEG images"
	@echo "  - Custom binary formats"
