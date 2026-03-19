.PHONY: all clean core-aes core file-handlers analysis testing tests command-line-tools hsm-integration

# Default target
all: core-aes core hsm-integration file-handlers cli-tools analysis testing tests command-line-tools

# Component targets
tests: core-aes core file-handlers cli-tools analysis testing command-line-tools
	@$(MAKE) -C tests

command-line-tools: core-aes core hsm-integration file-handlers cli-tools analysis
	@$(MAKE) -C command-line-tools

file-handlers: core analysis
	@$(MAKE) -C file-handlers

cli-tools: core
	@$(MAKE) -C cli-tools

core: core-aes
	@$(MAKE) -C core-crypto/src

hsm-integration: core
	@$(MAKE) -C hsm-integration

core-aes:
	@$(MAKE) -C core-crypto/aes

analysis:
	@$(MAKE) -C analysis

testing:
	@$(MAKE) -C testing

clean:
	@$(MAKE) -C hsm-integration clean
	@$(MAKE) -C command-line-tools clean
	@$(MAKE) -C tests clean
	@$(MAKE) -C file-handlers clean
	@$(MAKE) -C cli-tools clean
	@$(MAKE) -C core-crypto/src clean
	@$(MAKE) -C core-crypto/aes clean
	@$(MAKE) -C analysis clean
	@$(MAKE) -C testing clean
	rm -rf lib/* bin/* obj/*

install:
	echo "Installing is not supported"

help:
	$(call show_help)
