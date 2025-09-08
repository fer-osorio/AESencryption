# metrics-analysis/Makefile
include ../common.mk
include ../config.mk

# Local configuration
MODULE_NAME = metrics-analysis
PROJECT_ROOT := $(call find-project-root)
LIBDIR = $(PROJECT_ROOT)/lib
TARGET_LIB = $(LIBDIR)/libmetricsanalysis.a

# Local source directory and object directory
SRCDIR = ./src
OBJDIR = $(PROJECT_ROOT)/obj/$(notdir $(CURDIR))

# Local includes
INCDIR = include
INCLUDES = -I$(INCDIR)

# Source files
SOURCES = $(wildcard $(SRCDIR)/*.cpp)
OBJECTS = $(SOURCES:$(SRCDIR)/%.cpp=$(OBJDIR)/%.o)

# Dependencies on other modules
DEPS =

# Default target
all: $(TARGET_LIB)

# Library target
$(TARGET_LIB): $(OBJECTS) | $(LIBDIR) $(OBJDIR)
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
	$(call print_success,"Cleaned metrics-analysis module")

# Dependency inclusion
$(eval $(include_deps))
