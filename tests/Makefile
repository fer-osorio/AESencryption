# Include common functions and utilities
include ../common.mk
ifneq ($(BUILD_TYPE),debug)
	BUILD_TYPE = test
endif
$(info $(BUILD_TYPE))
include ../config.mk

# Local configuration. Since this is the test module, local configuration is fundamentally different.
TESTS_ROOT := $(CURDIR)
MODULE_NAME = $(notdir $(CURDIR))
# Objects and binaries are contained in this same module
OBJDIR = $(TESTS_ROOT)/obj
BINDIR = $(TESTS_ROOT)/bin
MODULE_DIRECTORIES := $(shell find . -mindepth 1 -maxdepth 1 -type d -print0 | xargs -0 -n 1 basename)
# Necessary for finding dependencies
PROJECT_ROOT := $(call find-project-root)

MAKEFILE_DEBUG =? FALSE
ifeq ($(MAKEFILE_DEBUG),TRUE)
    $(info MODULE_DIRECTORIES:          $(MODULE_DIRECTORIES))
    $(info )
endif

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

# Local includes and libraries
INCLUDES = \
    -I./include \
    -I$(PROJECT_ROOT)/testing/include \
    -I$(PROJECT_ROOT)/testing/include/test-vectors \
    -I$(PROJECT_ROOT)/cli-tools/include \
    -I$(PROJECT_ROOT)/file-handlers/include \
    -I$(PROJECT_ROOT)/core-crypto/include \
    -I$(PROJECT_ROOT)/core-crypto/aes/include \
    -I$(PROJECT_ROOT)/analysis/include \
    -I$(PROJECT_ROOT)/hsm-integration/include \
    -I$(PROJECT_ROOT)/third-party/stb

LDFLAGS += -L$(PROJECT_ROOT)/lib
LIBS = -lciphfortis_cli -lciphfortis_files -lciphfortis_core -lciphfortis_aes -lciphfortis_analysis -lciphfortis_testing -lciphfortis_hsm -ldl

# Define required dependencies (library files)
DEPS = \
    $(PROJECT_ROOT)/lib/libciphfortis_aes.a \
    $(PROJECT_ROOT)/lib/libciphfortis_core.a \
    $(PROJECT_ROOT)/lib/libciphfortis_analysis.a \
    $(PROJECT_ROOT)/lib/libciphfortis_files.a \
    $(PROJECT_ROOT)/lib/libciphfortis_cli.a \
    $(PROJECT_ROOT)/lib/libciphfortis_testing.a \
    $(PROJECT_ROOT)/lib/libciphfortis_hsm.a

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
	$(call check_dependencies)

# Build dependencies (optional - for convenience)
dependencies:
	$(call print_info,"Building project dependencies...")
	@$(MAKE) -C $(PROJECT_ROOT)/testing
	@$(MAKE) -C $(PROJECT_ROOT)/core-crypto/aes
	@$(MAKE) -C $(PROJECT_ROOT)/core-crypto/src
	@$(MAKE) -C $(PROJECT_ROOT)/hsm-integration
	@$(MAKE) -C $(PROJECT_ROOT)/analysis
	@$(MAKE) -C $(PROJECT_ROOT)/file-handlers
	@$(MAKE) -C $(PROJECT_ROOT)/cli-tools
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
		if $$test; then \
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
	@echo -e "$(COLOR_CYAN)DEPS:$(COLOR_NC)"
	@for dep in $(DEPS); do echo "  $$dep"; done
	@echo -e "$(COLOR_CYAN)UNIT_TESTS:$(COLOR_NC)"
	@for test in $(UNIT_TESTS); do echo "  $$test"; done
	@echo -e "$(COLOR_CYAN)INTEGRATION_TESTS:$(COLOR_NC)"
	@for test in $(INTEGRATION_TESTS); do echo "  $$test"; done
	@echo -e "$(COLOR_CYAN)SYSTEM_TESTS:$(COLOR_NC)"
	@for test in $(SYSTEM_TESTS); do echo "  $$test"; done
	@echo -e "$(COLOR_CYAN)TEST_UTILS_OBJECTS:$(COLOR_NC)"
	@for obj in $(TEST_UTILS_OBJECTS); do echo "  $$obj"; done
	@echo -e "$(COLOR_CYAN)TESTS_ROOT:$(COLOR_NC) $(TESTS_ROOT)"
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
