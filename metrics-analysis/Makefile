# metrics-analysis/Makefile
include ../common.mk

# Local configuration
MODULE_NAME = metrics-analysis
TARGET_LIB = $(LIBDIR)/libmetrics.a

# Source files
SOURCES = $(wildcard $(SRCDIR)/*.cpp)
OBJECTS = $(SOURCES:$(SRCDIR)/%.cpp=$(OBJDIR)/%.o)

# Local includes (in addition to common includes)
INCLUDES = -I$(INCDIR)

# Dependencies on other modules
DEPS =

# Default target
all: $(TARGET_LIB)

# Library target
$(TARGET_LIB): $(OBJECTS) | $(LIBDIR)
	$(call create_static_lib,$@,$(OBJECTS))

# Compilation rule for C++ files
$(eval $(compile_cxx_rule))

# Directory creation
$(OBJDIR) $(LIBDIR):
	$(call create_dir,$@)

# Clean target
clean:
	$(call clean_standard)
	@rm -f $(TARGET_LIB)
	$(call print_success,"Cleaned metrics-analysis module")
