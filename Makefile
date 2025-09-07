include common.mk

.PHONY: all clean data-encryption core file-handlers metrics-analysis tests #tools

# Default target
all: data-encryption core file-handlers metrics-analysis tests #tools

# Component targets
tests: file-handlers core data-encryption metrics-analysis
	@$(MAKE) -C tests

file-handlers: core
	@$(MAKE) -C file-handlers

core: data-encryption
	@$(MAKE) -C src

data-encryption:
	@$(MAKE) -C data-encryption

metrics-analysis:
	@$(MAKE) -C metrics-analysis

#tools: core file-handlers
#	@$(MAKE) -C tools

clean:
	@$(MAKE) -C data-encryption clean
	@$(MAKE) -C src clean
	@$(MAKE) -C file-handlers clean
	@$(MAKE) -C metrics-analysis clean
	@$(MAKE) -C tests clean
	rm -rf lib/* bin/* obj/*

install:
	echo "Installing is not supported"

help:
	$(call show_help)
