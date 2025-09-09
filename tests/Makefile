# Include common functions and utilities
include ../common.mk
include ../config.mk

# Local configuration
MODULE_NAME = tests
PROJECT_ROOT := $(call find-project-root)

# Local directories
SRCDIR = src
OBJDIR = $(PROJECT_ROOT)/obj/$(notdir $(CURDIR))
BINDIR = bin
UNIT_DIR = unit
INTEGRATION_DIR = integration

# Local includes and libraries
INCLUDES = -I./include -I../data-encryption/include
LDFLAGS = -L$(PROJECT_ROOT)/lib
LIBS = -laesencryption_c  -laesencryption_cpp  -lfilehandlers  -lmetricsanalysis

# Define required dependencies (library files)
REQUIRED_DEPS = \
	$(PROJECT_ROOT)/lib/libaesencryption_c.a \
	$(PROJECT_ROOT)/lib/libaesencryption_cpp.a \
	$(PROJECT_ROOT)/lib/libfilehandlers.a \
	$(PROJECT_ROOT)/lib/libmetricsanalysis.a

# Source files
TEST_UTILS_SOURCES = $(wildcard $(SRCDIR)/*.cpp)
UNIT_TEST_SOURCES = $(wildcard $(UNIT_DIR)/*.cpp)
INTEGRATION_TEST_SOURCES = $(wildcard $(INTEGRATION_DIR)/*.cpp)

# Object files
TEST_UTILS_OBJECTS = $(TEST_UTILS_SOURCES:$(SRCDIR)/%.cpp=$(OBJDIR)/$(SRCDIR)/%.o)
UNIT_TEST_OBJECTS = $(UNIT_TEST_SOURCES:$(UNIT_DIR)/%.cpp=$(OBJDIR)/unit/%.o)
INTEGRATION_TEST_OBJECTS = $(INTEGRATION_TEST_SOURCES:$(INTEGRATION_DIR)/%.cpp=$(OBJDIR)/integration/%.o)

# Test executables
UNIT_TESTS = $(UNIT_TEST_SOURCES:$(UNIT_DIR)/%.cpp=$(BINDIR)/%)
INTEGRATION_TESTS = $(INTEGRATION_TEST_SOURCES:$(INTEGRATION_DIR)/%.cpp=$(BINDIR)/%)

ALL_TESTS = $(UNIT_TESTS) #$(INTEGRATION_TESTS)

.PHONY: all clean unit integration check-deps help debug-vars run-unit run-integration run-all

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
		$(call print_error,"Missing dependencies:$$missing_deps"); \
		$(call print_info,"Build required modules first:"); \
		$(call print_info,"  make -C $(PROJECT_ROOT)/data-encryption"); \
		$(call print_info,"  make -C $(PROJECT_ROOT)/src"); \
		$(call print_info,"  make -C $(PROJECT_ROOT)/file-handlers"); \
		$(call print_info,"  make -C $(PROJECT_ROOT)/metrics-analysis"); \
		$(call print_warning,"Run 'make dependencies' if you want to build them automatically"); \
		exit 1; \
	else \
		$(call print_success,"All dependencies found"); \
	fi

# Build dependencies (optional - for convenience)
dependencies:
	$(call print_info,"Building project dependencies...")
	@$(MAKE) -C $(PROJECT_ROOT)/data-encryption
	@$(MAKE) -C $(PROJECT_ROOT)/src
	@$(MAKE) -C $(PROJECT_ROOT)/file-handlers
	@$(MAKE) -C $(PROJECT_ROOT)/metrics-analysis
	$(call print_success,"All dependencies built successfully")

# Unit tests
unit: check-deps $(UNIT_TESTS)

# Integration tests
integration: check-deps $(INTEGRATION_TESTS)

# Build individual unit test
$(BINDIR)/test_%: $(OBJDIR)/$(UNIT_DIR)/test_%.o $(TEST_UTILS_OBJECTS) | $(BINDIR)
	$(call create_dir,$(BINDIR))
	$(call print_building,"Unit test executable: $@")
	@$(CXX) $^ -o $@ $(LDFLAGS) $(LIBS) -fsanitize=address -fsanitize=undefined
	$(call print_success,"Built unit test: $@")

# Build individual integration test
$(BINDIR)/integration_test_%: $(OBJDIR)/integration/test_%.o $(TEST_UTILS_OBJECTS) | $(BINDIR)
	$(call create_dir,$(BINDIR))
	$(call print_building,"Integration test executable: $@")
	@$(CXX) $^ -o $@ $(LDFLAGS) $(LIBS)
	$(call print_success,"Built integration test: $@")

# Compile test utility objects using common.mk function
$(OBJDIR)/$(SRCDIR)/%.o: $(SRCDIR)/%.cpp
	$(call compile_cpp_rule,$<,$@)

# Compile unit test objects using common.mk function
$(OBJDIR)/$(UNIT_DIR)/%.o: $(UNIT_DIR)/%.cpp
	$(call compile_cpp_rule,$<,$@)

# Compile integration test objects using common.mk function
$(OBJDIR)/integration/%.o: $(INTEGRATION_DIR)/%.cpp
	$(call compile_cpp_rule,$<,$@)

# Create directories (now handled by common.mk functions, but kept for explicit dependencies)
$(OBJDIR) $(BINDIR) $(OBJDIR)/$(SRCDIR) $(OBJDIR)/$(UNIT_DIR) $(OBJDIR)/integration:
	$(call create_dir,$@)

# Run tests with improved output
run-unit: unit
	$(call print_info,"Running unit tests...")
	@failed=0; \
	for test in $(UNIT_TESTS); do \
		if [ -f "$$test" ]; then \
			$(call print_building,"Executing: $$test"); \
			if ./$$test; then \
				$(call print_success,"PASSED: $$test"); \
			else \
				$(call print_error,"FAILED: $$test"); \
				failed=1; \
			fi; \
		else \
			$(call print_warning,"Test executable not found: $$test"); \
		fi; \
	done; \
	if [ $$failed -eq 0 ]; then \
		$(call print_success,"All unit tests passed!"); \
	else \
		$(call print_error,"Some unit tests failed!"); \
		exit 1; \
	fi

run-integration: integration
	$(call print_info,"Running integration tests...")
	@failed=0; \
	for test in $(INTEGRATION_TESTS); do \
		if [ -f "$$test" ]; then \
			$(call print_building,"Executing: $$test"); \
			if ./$$test; then \
				$(call print_success,"PASSED: $$test"); \
			else \
				$(call print_error,"FAILED: $$test"); \
				failed=1; \
			fi; \
		else \
			$(call print_warning,"Test executable not found: $$test"); \
		fi; \
	done; \
	if [ $$failed -eq 0 ]; then \
		$(call print_success,"All integration tests passed!"); \
	else \
		$(call print_error,"Some integration tests failed!"); \
		exit 1; \
	fi

run-all: run-unit run-integration
	$(call print_success,"All tests completed successfully!")

# Enhanced clean using common.mk function
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
	@echo -e "$(COLOR_CYAN)TEST_UTILS_OBJECTS:$(COLOR_NC)"
	@for obj in $(TEST_UTILS_OBJECTS); do echo "  $$obj"; done
	@echo -e "$(COLOR_CYAN)PROJECT_ROOT:$(COLOR_NC) $(PROJECT_ROOT)"
	@echo -e "$(COLOR_CYAN)OBJDIR:$(COLOR_NC) $(OBJDIR)"
	@echo -e "$(COLOR_CYAN)BINDIR:$(COLOR_NC) $(BINDIR)"

# Help target using common.mk function with test-specific additions
help:
	$(call print_info,"Test Makefile Help")
	@echo -e "$(COLOR_BLUE)Available targets:$(COLOR_NC)"
	@echo -e "  all           - Build all tests (default)"
	@echo -e "  unit          - Build only unit tests"
	@echo -e "  integration   - Build only integration tests"
	@echo -e "  check-deps    - Check if dependencies exist"
	@echo -e "  dependencies  - Build project dependencies (optional)"
	@echo -e "  run-unit      - Build and run unit tests"
	@echo -e "  run-integration - Build and run integration tests"
	@echo -e "  run-all       - Build and run all tests"
	@echo -e "  clean         - Clean all build artifacts"
	@echo -e "  debug-vars    - Show makefile variables"
	@echo -e "  help          - Show this help"
	@echo -e ""
	@echo -e "$(COLOR_BLUE)Usage examples:$(COLOR_NC)"
	@echo -e "  make                    # Build all tests (checks deps first)"
	@echo -e "  make check-deps         # Only check dependencies"
	@echo -e "  make dependencies       # Build missing dependencies"
	@echo -e "  make run-unit          # Build and run unit tests"
	@echo -e "  make clean all         # Clean and rebuild"
	@echo -e "  make debug-vars        # Show variables for debugging"

# Include dependency files (using common.mk function)
$(call include_deps)
