# Include common functions and utilities
include ../common.mk
include ../config.mk

# Local configuration
MODULE_NAME = $(notdir $(CURDIR))
PROJECT_ROOT := $(call find-project-root)
MODULE_DIRECTORIES := $(shell find . -mindepth 1 -maxdepth 1 -type d -print0 | xargs -0 -n 1 basename)
MAKEFILE_DEBUG =? FALSE
ifeq ($(MAKEFILE_DEBUG),TRUE)
    $(info MODULE_DIRECTORIES:          $(MODULE_DIRECTORIES))
    $(info )
endif
SRCDIR = src

# Tests directories
UNIT_DIR = unit
INTEGRATION_DIR = integration
SYSTEM_DIR = system
TEST_DIRS = $(UNIT_DIR) $(INTEGRATION_DIR) $(SYSTEM_DIR)

# Test categories
TEST_CATEGORIES = $(shell echo $(TEST_DIRS) | tr '[:lower:]' '[:upper:]')
ifeq ($(MAKEFILE_DEBUG),TRUE)
    $(info TEST_CATEGORIES :          $(TEST_CATEGORIES))
    $(info )
endif

# Binaries and objects directories
BINDIR = bin
OBJDIR = obj

# Local includes and libraries
INCLUDES = \
    -I./include \
    -I$(PROJECT_ROOT)/crypto-cli/include \
    -I$(PROJECT_ROOT)/file-handlers/include \
    -I$(PROJECT_ROOT)/include \
    -I$(PROJECT_ROOT)/data-encryption/include \
    -I$(PROJECT_ROOT)/metrics-analysis/include

LDFLAGS += -L$(PROJECT_ROOT)/lib
LIBS = -lcli -lfilehandlers -laesencryption_cpp  -laesencryption_c  -lmetricsanalysis

# Define required dependencies (library files)
REQUIRED_DEPS = \
    $(PROJECT_ROOT)/lib/libaesencryption_c.a \
    $(PROJECT_ROOT)/lib/libaesencryption_cpp.a \
    $(PROJECT_ROOT)/lib/libfilehandlers.a \
    $(PROJECT_ROOT)/lib/libmetricsanalysis.a \
    $(PROJECT_ROOT)/lib/libcli.a

# Source files
SOURCES = $(call find_local_sources,cpp)
ifeq ($(MAKEFILE_DEBUG),TRUE)
    $(info SOURCES:          $(notdir $(SOURCES)))
    $(info )
endif

TEST_UTILS_SOURCES = $(wildcard $(SRCDIR)/*.cpp)
ifeq ($(MAKEFILE_DEBUG),TRUE)
    $(info TEST_UTILS_SOURCES:          $(notdir $(TEST_UTILS_SOURCES)))
    $(info )
endif
TEST_UTILS_OBJECTS = $(TEST_UTILS_SOURCES:$(SRCDIR)/%.cpp=$(OBJDIR)/$(SRCDIR)/%.o)
ifeq ($(MAKEFILE_DEBUG),TRUE)
    $(info TEST_UTILS_OBJECTS:          $(notdir $(TEST_UTILS_OBJECTS)))
    $(info )
endif

# Object files
OBJECTS = $(foreach md,$(MODULE_DIRECTORIES), \
        $(call sources_to_objects,$(filter $(md)/%,$(SOURCES)),$(OBJDIR)/$(md),cpp) \
)
ifeq ($(MAKEFILE_DEBUG),TRUE)
    $(info OBJECTS:          $(notdir $(OBJECTS)))
    $(info )
endif

# Binary files
BINARIES = $(foreach td,$(TEST_DIRS), \
        $(call objects_to_binaries,$(filter $(OBJDIR)/$(td)/%,$(OBJECTS)),$(BINDIR)/$(td)) \
)
ifeq ($(MAKEFILE_DEBUG),TRUE)
    $(info BINARIES:         $(notdir $(BINARIES)))
    $(info )
endif

# Usage $(eval $(call filter_tests,TEST_CATEGORY))
# Example: TEST_CATEGORY = UNIT, then the output is
# UNIT_TESTS = $(filter $(BINDIR)/$(UNIT_DIR)/%,$(BINARIES))
define filter_tests
$(1)_TESTS = $$(filter $$(BINDIR)/$$($(1)_DIR)/%,$$(BINARIES))
endef

# Test executables
$(foreach tc,$(TEST_CATEGORIES), \
        $(eval $(call filter_tests,$(tc))) \
)

ALL_TESTS = $(UNIT_TESTS) $(INTEGRATION_TESTS) $(SYSTEM_TESTS)

ifeq ($(MAKEFILE_DEBUG),TRUE)
    $(info UNIT_TESTS:        $(notdir $(UNIT_TESTS)))
    $(info )
    $(info INTEGRATION_TESTS: $(notdir $(INTEGRATION_TESTS)))
    $(info )
    $(info SYSTEM_TESTS:      $(notdir $(SYSTEM_TESTS)))
    $(info )
    $(info ALL_TESTS:         $(notdir $(ALL_TESTS)))
    $(info )
endif
#$(error Debuggin. Stop.)

.PHONY: all clean unit integration system check-deps help debug-vars run-unit run-integration run-all

# Default target
all: check-deps $(ALL_TESTS)

# Check dependencies
check-deps:
	$(call print_info,"Checking project dependencies...")
	@missing_deps=""; \
	for dep in $(REQUIRED_DEPS); do \
		if [ ! -f "$$dep" ]; then \
			missing_deps="$$missing_deps $$dep"; \
		fi; \
	done; \
	if [ -n "$$missing_deps" ]; then \
		echo -e "$(COLOR_RED)[ERROR]$(COLOR_NC) Missing dependencies:$$missing_deps"; \
		echo -e "$(COLOR_BLUE)[INFO]$(COLOR_NC) Build required modules first:"; \
		echo -e "$(COLOR_BLUE)[INFO]$(COLOR_NC)   make -C $(PROJECT_ROOT)/data-encryption"; \
		echo -e "$(COLOR_BLUE)[INFO]$(COLOR_NC)   make -C $(PROJECT_ROOT)/src"; \
		echo -e "$(COLOR_BLUE)[INFO]$(COLOR_NC)   make -C $(PROJECT_ROOT)/file-handlers"; \
		echo -e "$(COLOR_BLUE)[INFO]$(COLOR_NC)   make -C $(PROJECT_ROOT)/metrics-analysis"; \
		echo -e "$(COLOR_YELLOW)[WARNING]$(COLOR_NC) Run 'make dependencies' if you want to build them automatically"; \
		exit 1; \
	else \
		echo -e "$(COLOR_GREEN)[SUCCESS]$(COLOR_NC) All dependencies found"; \
	fi

# Build dependencies (optional - for convenience)
dependencies:
	$(call print_info,"Building project dependencies...")
	@$(MAKE) -C $(PROJECT_ROOT)/data-encryption
	@$(MAKE) -C $(PROJECT_ROOT)/src
	@$(MAKE) -C $(PROJECT_ROOT)/file-handlers
	@$(MAKE) -C $(PROJECT_ROOT)/metrics-analysis
	@$(MAKE) -C $(PROJECT_ROOT)/crypto-cli
	$(call print_success,"All dependencies built successfully")

# Unit tests
unit: check-deps $(UNIT_TESTS)

# Integration tests
integration: check-deps $(INTEGRATION_TESTS)

# System tests
system: check-deps $(SYSTEM_TESTS)

# Usage $(eval $(call build_test_category_executables,test_category))
define build_test_category_executables
$$(BINDIR)/$$($(1)_DIR)/test_%: $$(OBJDIR)/$$($(1)_DIR)/test_%.o $$(TEST_UTILS_OBJECTS) | $$(BINDIR)/$$($(1)_DIR) $$(OBJDIR)
	$(call print_building,"$(1) test executable: $$@")
	$(call create_executable,$$@,$$^)
	$(call print_success,"Built $(1) test: $$@")
endef

# Build individual unit test
$(eval $(call build_test_category_executables,UNIT))

# Build individual integration test
$(eval $(call build_test_category_executables,INTEGRATION))

# Build individual system test
$(eval $(call build_test_category_executables,SYSTEM))

# Usage $(eval $(call compile_test_category_objects,test_category))
define compile_test_category_objects
$$(OBJDIR)/$$($(1)_DIR)/%.o: $$($(1)_DIR)/%.cpp | $$(OBJDIR)/$$($(1)_DIR)
	$(call compile_cpp_rule,$$<,$$@)
endef

# Compile unit test objects
$(eval $(call compile_test_category_objects,UNIT))

# Compile integration test objects
$(eval $(call compile_test_category_objects,INTEGRATION))

# Compile integration test objects
$(eval $(call compile_test_category_objects,SYSTEM))

# Compile test utility objects
$(OBJDIR)/$(SRCDIR)/%.o: $(SRCDIR)/%.cpp | $(OBJDIR)/$(SRCDIR)
	$(call compile_cpp_rule,$<,$@)

# Create directories (handled by common.mk functions, but kept for explicit dependencies)
$(OBJDIR) $(BINDIR) \
$(OBJDIR)/$(SRCDIR) $(OBJDIR)/$(UNIT_DIR) $(OBJDIR)/$(INTEGRATION_DIR) $(OBJDIR)/$(SYSTEM_DIR) \
$(BINDIR)/$(INTEGRATION_DIR) $(BINDIR)/$(UNIT_DIR) $(BINDIR)/$(SYSTEM_DIR):
	$(call create_dir,$@)

# Usage $(call run_tests,category)
define run_tests
@failed=0; \
for test in $($(1)_TESTS); do \
	if [ -f "$$test" ]; then \
		$(call echo_building,"Executing: $$test"); \
		if ./$$test; then \
			$(call echo_success,"PASSED: $$test"); \
		else \
			$(call echo_error,"FAILED: $$test"); \
			failed=1; \
		fi; \
	else \
		$(call echo_warning,"Test executable not found: $$test"); \
	fi; \
done; \
if [ $$failed -eq 0 ]; then \
	$(call echo_success,"All $(1) tests passed!"); \
else \
	$(call echo_error,"Some $(1) tests failed!"); \
	exit 1; \
fi
endef

# Run tests with improved output
run-unit: unit
	$(call print_info,"Running unit tests...")
	$(call run_tests,UNIT)

run-integration: integration
	$(call print_info,"Running integration tests...")
	$(call run_tests,INTEGRATION)

run-system: system
	$(call print_info,"Running system tests...")
	$(call run_tests,SYSTEM)

run-all: run-unit run-integration run-system
	$(call print_success,"All tests completed successfully!")

clean:
	$(call print_info,"Cleaning test artifacts...")
	$(call clean_standard)
	$(call print_info,"Cleaning test binaries")
	@rm -rf $(BINDIR)
	$(call print_info,"Cleaning test results")
	@rm -rf results/*
	$(call print_success,"Test cleanup completed")

# Debug target - shows variables with better formatting
debug-vars:
	$(call print_info,"Makefile Variables:")
	@echo -e "$(COLOR_CYAN)REQUIRED_DEPS:$(COLOR_NC)"
	@for dep in $(REQUIRED_DEPS); do echo "  $$dep"; done
	@echo -e "$(COLOR_CYAN)UNIT_TESTS:$(COLOR_NC)"
	@for test in $(UNIT_TESTS); do echo "  $$test"; done
	@echo -e "$(COLOR_CYAN)INTEGRATION_TESTS:$(COLOR_NC)"
	@for test in $(INTEGRATION_TESTS); do echo "  $$test"; done
	@echo -e "$(COLOR_CYAN)SYSTEM_TESTS:$(COLOR_NC)"
	@for test in $(SYSTEM_TESTS); do echo "  $$test"; done
	@echo -e "$(COLOR_CYAN)TEST_UTILS_OBJECTS:$(COLOR_NC)"
	@for obj in $(TEST_UTILS_OBJECTS); do echo "  $$obj"; done
	@echo -e "$(COLOR_CYAN)PROJECT_ROOT:$(COLOR_NC) $(PROJECT_ROOT)"
	@echo -e "$(COLOR_CYAN)OBJDIR:$(COLOR_NC) $(OBJDIR)"
	@echo -e "$(COLOR_CYAN)BINDIR:$(COLOR_NC) $(BINDIR)"

# Help target using common.mk function with test-specific additions
help:
	$(call print_info,"Test Makefile Help")
	@echo -e "$(COLOR_BLUE)Available targets:$(COLOR_NC)"
	@echo -e "  all              - Build all tests (default)"
	@echo -e "  unit             - Build only unit tests"
	@echo -e "  integration      - Build only integration tests"
	@echo -e "  system           - Build only system tests"
	@echo -e "  check-deps       - Check if dependencies exist"
	@echo -e "  dependencies     - Build project dependencies (optional)"
	@echo -e "  run-unit         - Build and run unit tests"
	@echo -e "  run-integration  - Build and run integration tests"
	@echo -e "  run-system       - Build and run integration tests"
	@echo -e "  run-all          - Build and run all tests"
	@echo -e "  clean            - Clean all build artifacts"
	@echo -e "  debug-vars       - Show makefile variables"
	@echo -e "  help             - Show this help"
	@echo -e ""
	@echo -e "$(COLOR_BLUE)Usage examples:$(COLOR_NC)"
	@echo -e "  make               # Build all tests (checks deps first)"
	@echo -e "  make check-deps    # Only check dependencies"
	@echo -e "  make dependencies  # Build missing dependencies"
	@echo -e "  make run-unit      # Build and run unit tests"
	@echo -e "  make clean all     # Clean and rebuild"
	@echo -e "  make debug-vars    # Show variables for debugging"

# Include dependency files
$(eval $(call include_deps))
