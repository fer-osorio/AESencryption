include common.mk

.PHONY: all clean test data-encryption core file-handlers tools metrics-analysis

# Default target
all: core file-handlers tools examples

# Component targets
core: data-encryption
	@$(MAKE) -C src

data-encryption:
	@$(MAKE) -C data-encryption

file-handlers: core
	@$(MAKE) -C file-handlers

metrics-analysis:
	@$(MAKE) -C metrics-analysis

test: core file-handlers
	@$(MAKE) -C tests

tools: core file-handlers
	@$(MAKE) -C tools

clean:
	@$(MAKE) -C data-encryption clean
	@$(MAKE) -C src clean
	@$(MAKE) -C file-handlers clean
	#@$(MAKE) -C tools clean
	@$(MAKE) -C tests clean
	rm -rf lib/* bin/* obj/*

install:
	echo "Installing is not supported"

help:
	$(call show_help)
