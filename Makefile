# Makefile to build suri-tester.go into suri-tester binary

# Default target
all: suri-tester

# Build the binary
suri-tester: suri-tester.go
	go build -o suri-tester suri-tester.go

# Clean up
clean:
	rm -f suri-tester

# Install Go if needed (for RHEL/Debian compatibility, but assuming Go is installed)
# This is optional and not required for building if Go is already present.
install-go:
ifeq ($(shell uname -s),Linux)
	@if [ -f /etc/redhat-release ]; then \
		sudo yum install -y golang; \
	elif [ -f /etc/debian_version ]; then \
		sudo apt-get update && sudo apt-get install -y golang-go; \
	else \
		echo "Unsupported Linux distribution"; \
		exit 1; \
	fi
else
	@echo "This Makefile is intended for Linux (RHEL/Debian)"
	exit 1
endif