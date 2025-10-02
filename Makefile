include common.mk

.PHONY: all clean data-encryption core file-handlers metrics-analysis tests #tools

# Default target
all: data-encryption core file-handlers cli metrics-analysis tests

# Component targets
tests: data-encryption core file-handlers cli metrics-analysis
	@$(MAKE) -C tests

file-handlers: core metrics-analysis
	@$(MAKE) -C file-handlers

cli: core
	@$(MAKE) -C CLI

core: data-encryption
	@$(MAKE) -C src

data-encryption:
	@$(MAKE) -C data-encryption

metrics-analysis:
	@$(MAKE) -C metrics-analysis

clean:
	@$(MAKE) -C tests clean
	@$(MAKE) -C file-handlers clean
	@$(MAKE) -C CLI clean
	@$(MAKE) -C src clean
	@$(MAKE) -C data-encryption clean
	@$(MAKE) -C metrics-analysis clean
	rm -rf lib/* bin/* obj/*

install:
	echo "Installing is not supported"

help:
	$(call show_help)
