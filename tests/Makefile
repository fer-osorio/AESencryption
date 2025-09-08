include ../config.mk

# Project structure paths
PROJECT_ROOT = ..

LDFLAGS = -L$(PROJECT_ROOT)/lib
LIBS = -laesencryption_c -laesencryption_cpp -lfile_handlers -lmetrics

# Directories
SRCDIR = src
OBJDIR = $(PROJECT_ROOT)/obj/$(notdir $(CURDIR))
BINDIR = bin
UNIT_DIR = unit
#INTEGRATION_DIR = integration

# Source files
TEST_UTILS_SOURCES = $(wildcard $(SRCDIR)/*.cpp)
UNIT_TEST_SOURCES = $(wildcard $(UNIT_DIR)/*.cpp)
#INTEGRATION_TEST_SOURCES = $(wildcard $(INTEGRATION_DIR)/*.cpp)

# Object files
TEST_UTILS_OBJECTS = $(TEST_UTILS_SOURCES:$(SRCDIR)/%.cpp=$(OBJDIR)/$(SRCDIR)/%.o)
UNIT_TEST_OBJECTS = $(UNIT_TEST_SOURCES:$(UNIT_DIR)/%.cpp=$(OBJDIR)/unit/%.o)
#INTEGRATION_TEST_OBJECTS = $(INTEGRATION_TEST_SOURCES:$(INTEGRATION_DIR)/%.cpp=$(OBJDIR)/integration/%.o)

# Test executables
UNIT_TESTS = $(UNIT_TEST_SOURCES:$(UNIT_DIR)/%.cpp=$(BINDIR)/%)
#INTEGRATION_TESTS = $(INTEGRATION_TEST_SOURCES:$(INTEGRATION_DIR)/%.cpp=$(BINDIR)/%)

ALL_TESTS = $(UNIT_TESTS) #$(INTEGRATION_TESTS)

.PHONY: all clean unit dependencies #integration run-unit run-integration run-all

# Default target
all: $(ALL_TESTS) # dependencies

# Build dependencies first
dependencies:
	@echo "Building dependencies..."
	@$(MAKE) -C $(PROJECT_ROOT)/data-encryption
	@$(MAKE) -C $(PROJECT_ROOT)/src
	@$(MAKE) -C $(PROJECT_ROOT)/file-handlers
	@$(MAKE) -C $(PROJECT_ROOT)/metrics-analysis

# Unit tests
unit: $(UNIT_TESTS) #dependencies

# Integration tests
#integration: dependencies $(INTEGRATION_TESTS)

$(info $(BINDIR)/test_)

# Build individual unit test
$(BINDIR)/test_%: $(OBJDIR)/unit/test_%.o $(TEST_UTILS_OBJECTS) | $(BINDIR) $(OBJDIR)
	$(CXX) $^ -o $@ $(LDFLAGS) $(LIBS)

# Build individual integration test
#$(BINDIR)/test_%: $(OBJDIR)/integration/test_%.o $(TEST_UTILS_OBJECTS) | $(BINDIR)
#	$(CXX) $^ -o $@ $(LDFLAGS) $(LIBS)

# Compile test utility objects
$(OBJDIR)/$(SRCDIR)/%.o: $(SRCDIR)/%.cpp | $(OBJDIR)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

# Compile unit test objects
$(OBJDIR)/unit/%.o: $(UNIT_DIR)/%.cpp | $(OBJDIR)/unit
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

# Compile integration test objects
$(OBJDIR)/integration/%.o: $(INTEGRATION_DIR)/%.cpp | $(OBJDIR)/integration
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

# Create directories
$(OBJDIR) $(BINDIR) $(OBJDIR)/unit $(OBJDIR)/integration:
	mkdir -p $@

# Run tests
run-unit: unit
	@echo "Running unit tests..."
	@for test in $(UNIT_TESTS); do \
		echo "Running $$test..."; \
		./$$test || exit 1; \
	done

run-integration: integration
	@echo "Running integration tests..."
	@for test in $(INTEGRATION_TESTS); do \
		echo "Running $$test..."; \
		./$$test || exit 1; \
	done

run-all: run-unit run-integration
	@echo "All tests completed successfully!"

clean:
	rm -rf $(OBJDIR) $(BINDIR) results/*

# Debug target - shows variables
debug:
	@echo "UNIT_TESTS: $(UNIT_TESTS)"
	@echo "INTEGRATION_TESTS: $(INTEGRATION_TESTS)"
	@echo "TEST_UTILS_OBJECTS: $(TEST_UTILS_OBJECTS)"
