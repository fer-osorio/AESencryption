# command-line-tools/Makefile
include ../common.mk
include ../config.mk

# Local configuration
MODULE_NAME = $(notdir $(CURDIR))
PROJECT_ROOT := $(call find-project-root)
BINDIR = $(PROJECT_ROOT)/bin/$(MODULE_NAME)
MODULE_DIRECTORIES := $(shell find . -type d -print0 | xargs -0 -n 1 basename)
#TARGET_LIB = $(BINDIR)/libmetricsanalysis.a

# Local source directory and object directory
#SRCDIR = ./src
OBJDIR = $(PROJECT_ROOT)/obj/$(MODULE_NAME)

# Local includes
INCDIR = include
INCLUDES = -I$(PROJECT_ROOT)/$(INCDIR) $(PROJECT_ROOT)/file-handlers/$(INCDIR) $(PROJECT_ROOT)/command-line-tools/$(INCDIR)
LIBS = -lcli -lfilehandlers -laesencryption_cpp  -laesencryption_c  -lmetricsanalysis

# Source files
SOURCES = $(call find_sources,./,cpp)
OBJECTS = $(SOURCES:$(SRCDIR)/%.cpp=$(OBJDIR)/%.o)

# Dependencies on other modules
DEPS =

# Default target
all: $(TARGET_LIB)

# Library target
#$(TARGET_LIB): $(OBJECTS) | $(BINDIR) $(OBJDIR)
#	$(call create_static_lib,$@,$(OBJECTS))

# Build executables
$(BINDIR)/%: $(OBJDIR)/%.o $(LIBS)
	$(call create_executable,$@,$^,)

# Compilation rule for C++ files
$(OBJDIR)/%.o: %.cpp | $(OBJDIR)
	$(call compile_cpp_rule,$<,$@,$(INCLUDES))

# Directory creation
$(OBJDIR) $(BINDIR):
	$(call create_dir,$@)

# Clean target
clean:
	$(call clean_standard)
	@rm -f $(TARGET_LIB)
	$(call print_success,"Cleaned command-line-tools module")

# Dependency inclusion
$(eval $(include_deps))
