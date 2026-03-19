# hsm/Makefile
include ../common.mk
include ../config.mk

# Module configuration
MODULE_NAME  = $(notdir $(CURDIR))
PROJECT_ROOT := $(call find-project-root)
LIBDIR       = $(PROJECT_ROOT)/lib
TARGET_LIB   = $(LIBDIR)/libciphfortis_hsm.a

# Object directory
OBJDIR = $(PROJECT_ROOT)/obj/$(notdir $(CURDIR))

# Includes: module headers + PKCS#11 header via pkg-config (fallback to system path)
PKCS11_INC := $(shell pkg-config --cflags p11-kit-1 2>/dev/null || echo "-I/usr/include/p11-kit-1")
INCLUDES    = -I$(PROJECT_ROOT)/hsm-integration/$(INCDIR) -I$(PROJECT_ROOT)/core-crypto/include $(PKCS11_INC)

# Source files and objects
SOURCES = $(wildcard $(SRCDIR)/*.cpp)
OBJECTS = $(SOURCES:$(SRCDIR)/%.cpp=$(OBJDIR)/%.o)

# Default target
all: $(TARGET_LIB)

# Static library creation
$(TARGET_LIB): $(OBJECTS) | $(LIBDIR) $(OBJDIR)
	$(call create_static_lib,$@,$(OBJECTS))

# Compilation rule for C++ files
$(OBJDIR)/%.o: $(SRCDIR)/%.cpp | $(OBJDIR)
	$(call compile_cpp_rule,$<,$@)

# Directory creation
$(OBJDIR) $(LIBDIR):
	$(call create_dir,$@)

# Clean target
clean:
	$(call clean_standard)
	@rm -f $(TARGET_LIB)
	$(call print_success,"Cleaned $(MODULE_NAME) module")

# Dependency inclusion
$(eval $(include_deps))

.PHONY: all clean
