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
INCLUDES = \
    -I./include \
    -I$(PROJECT_ROOT)/CLI/include \
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
TEST_UTILS_SOURCES = $(wildcard $(SRCDIR)/*.cpp)
UNIT_TEST_SOURCES = $(wildcard $(UNIT_DIR)/*.cpp)
INTEGRATION_TEST_SOURCES = $(wildcard $(INTEGRATION_DIR)/*.cpp)
SOURCES = $(TEST_UTILS_SOURCES) $(UNIT_TEST_SOURCES) $(INTEGRATION_TEST_SOURCES)

# Object files
TEST_UTILS_OBJECTS = $(TEST_UTILS_SOURCES:$(SRCDIR)/%.cpp=$(OBJDIR)/$(SRCDIR)/%.o)
UNIT_TEST_OBJECTS = $(UNIT_TEST_SOURCES:$(UNIT_DIR)/%.cpp=$(OBJDIR)/$(UNIT_DIR)/%.o)
INTEGRATION_TEST_OBJECTS = $(INTEGRATION_TEST_SOURCES:$(INTEGRATION_DIR)/%.cpp=$(OBJDIR)/$(INTEGRATION_DIR)/%.o)
OBJECTS = $(TEST_UTILS_OBJECTS) $(UNIT_TEST_OBJECTS) $(INTEGRATION_TEST_OBJECTS)

# Test executables
UNIT_TESTS = $(UNIT_TEST_SOURCES:$(UNIT_DIR)/%.cpp=$(BINDIR)/$(UNIT_DIR)/%)
INTEGRATION_TESTS = $(INTEGRATION_TEST_SOURCES:$(INTEGRATION_DIR)/%.cpp=$(BINDIR)/$(INTEGRATION_DIR)/%)

#$(info LDFLAGS: $(LDFLAGS))
#$(info SOURCES: $(SOURCES))
#$(info OBJECTS: $(OBJECTS))
#$(info REQUIRED_DEPS: $(REQUIRED_DEPS))

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
	$(call print_success,"All dependencies built successfully")

# Unit tests
unit: check-deps $(UNIT_TESTS)

# Integration tests
integration: check-deps $(INTEGRATION_TESTS)

# Build individual unit test
$(BINDIR)/$(UNIT_DIR)/test_%: $(OBJDIR)/$(UNIT_DIR)/test_%.o $(TEST_UTILS_OBJECTS) | $(BINDIR)/$(UNIT_DIR) $(OBJDIR)
	$(call print_building,"Unit test executable: $@")
	$(call create_executable,$@,$^)
	$(call print_success,"Built unit test: $@")

# Build individual integration test
$(BINDIR)/$(INTEGRATION_DIR)/test_%: $(OBJDIR)/$(INTEGRATION_DIR)/test_%.o $(TEST_UTILS_OBJECTS) | $(BINDIR)/$(INTEGRATION_DIR) $(OBJDIR)
	$(call print_building,"Integration test executable: $@")
	$(call create_executable,$@,$^)
	$(call print_success,"Built integration test: $@")

# Compile test utility objects using common.mk function
$(OBJDIR)/$(SRCDIR)/%.o: $(SRCDIR)/%.cpp | $(OBJDIR)/$(SRCDIR)
	$(call compile_cpp_rule,$<,$@)

# Compile unit test objects using common.mk function
$(OBJDIR)/$(UNIT_DIR)/%.o: $(UNIT_DIR)/%.cpp | $(OBJDIR)/$(UNIT_DIR)
	$(call compile_cpp_rule,$<,$@)

# Compile integration test objects using common.mk function
$(OBJDIR)/$(INTEGRATION_DIR)/%.o: $(INTEGRATION_DIR)/%.cpp | $(OBJDIR)/$(INTEGRATION_DIR)
	$(call compile_cpp_rule,$<,$@)

# Create directories (handled by common.mk functions, but kept for explicit dependencies)
$(OBJDIR) $(BINDIR)/$(INTEGRATION_DIR) $(BINDIR)/$(UNIT_DIR) $(OBJDIR)/$(SRCDIR) $(OBJDIR)/$(UNIT_DIR) $(OBJDIR)/$(INTEGRATION_DIR):
	$(call create_dir,$@)

# Run tests with improved output
run-unit: unit
	$(call print_info,"Running unit tests...")
	@failed=0; \
	for test in $(UNIT_TESTS); do \
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
		$(call echo_success,"All unit tests passed!"); \
	else \
		$(call echo_error,"Some unit tests failed!"); \
		exit 1; \
	fi

run-integration: integration
	$(call print_info,"Running integration tests...")
	@failed=0; \
	for test in $(INTEGRATION_TESTS); do \
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
		$(call echo_success,"All integration tests passed!"); \
	else \
		$(call echo_error,"Some integration tests failed!"); \
		exit 1; \
	fi

run-all: run-unit run-integration
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
	@echo -e "  make                   # Build all tests (checks deps first)"
	@echo -e "  make check-deps        # Only check dependencies"
	@echo -e "  make dependencies      # Build missing dependencies"
	@echo -e "  make run-unit          # Build and run unit tests"
	@echo -e "  make clean all         # Clean and rebuild"
	@echo -e "  make debug-vars        # Show variables for debugging"

# Include dependency files
$(eval $(call include_deps))
