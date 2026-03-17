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
INCLUDES = -I$(PROJECT_ROOT)/file-handlers/$(INCDIR) \
           -I$(PROJECT_ROOT)/$(INCDIR) \
           -I$(PROJECT_ROOT)/metrics-analysis/$(INCDIR) \
           -I$(PROJECT_ROOT)/third-party/stb

# Dependencies on other modules
DEPS = $(LIBDIR)/libaesencryption_cpp.a $(LIBDIR)/libmetricsanalysis.a

# External libraries needed
LIBS = -L$(LIBDIR) -laesencryption_cpp -lmetricsanalysis

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

# Compile stb implementation without strict warnings (third-party code)
$(OBJDIR)/stb_impl.o: $(SRCDIR)/stb_impl.cpp | $(OBJDIR)
	$(call print_building,"C++ object stb:\n\t\t$@")
	@$(CXX) $(CXX_STANDARD) -I$(PROJECT_ROOT)/third-party/stb -w -MMD -MP -c $< -o $@
	$(call print_success,"Compiled:\n\t\t$@")

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
.PHONY: all clean check-deps dependencies setup-test-data list-formats

# List supported file formats
list-formats:
	@echo -e "$(COLOR_BLUE)Supported file formats:$(COLOR_NC)"
	@echo -e "  - Text files (.txt)"
	@echo -e "  - Bitmap images (.bmp)"
	@echo -e "  - Binary files (generic)"
	@echo -e "$(COLOR_YELLOW)Planned formats:$(COLOR_NC)"
	@echo -e "  - PNG images"
	@echo -e "  - JPEG images"
	@echo -e "  - Custom binary formats"
