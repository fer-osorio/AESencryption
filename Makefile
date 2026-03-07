.PHONY: all clean data-encryption core file-handlers metrics-analysis test-framework tests command-line-tools

# Default target
all: data-encryption core file-handlers crypto-cli metrics-analysis test-framework tests command-line-tools

# Component targets
tests: data-encryption core file-handlers crypto-cli metrics-analysis test-framework command-line-tools
	@$(MAKE) -C tests

command-line-tools: data-encryption core file-handlers crypto-cli metrics-analysis
	@$(MAKE) -C command-line-tools

file-handlers: core metrics-analysis
	@$(MAKE) -C file-handlers

crypto-cli: core
	@$(MAKE) -C crypto-cli

core: data-encryption
	@$(MAKE) -C src

data-encryption:
	@$(MAKE) -C data-encryption

metrics-analysis:
	@$(MAKE) -C metrics-analysis

test-framework:
	@$(MAKE) -C test-framework

clean:
	@$(MAKE) -C command-line-tools clean
	@$(MAKE) -C tests clean
	@$(MAKE) -C file-handlers clean
	@$(MAKE) -C crypto-cli clean
	@$(MAKE) -C src clean
	@$(MAKE) -C data-encryption clean
	@$(MAKE) -C metrics-analysis clean
	@$(MAKE) -C test-framework clean
	rm -rf lib/* bin/* obj/*

install:
	echo "Installing is not supported"

help:
	$(call show_help)
