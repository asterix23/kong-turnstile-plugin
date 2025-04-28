# Makefile for Kong Turnstile Go Plugin

# Variables
BINARY_NAME=kong-turnstile-plugin
GO_FILES=main.go

# Default target
all: build

# Build the Go plugin
build:
	@echo "Building $(BINARY_NAME)..."
	go build -o $(BINARY_NAME) $(GO_FILES)
	@echo "Build complete: $(BINARY_NAME)"

# Clean the build artifact
clean:
	@echo "Cleaning build artifacts..."
	rm -f $(BINARY_NAME)
	@echo "Clean complete."

# Ensure dependencies are downloaded (optional but good practice)
deps:
	@echo "Downloading dependencies..."
	go mod download

# Run Go formatter (optional)
fmt:
	@echo "Running go fmt..."
	go fmt ./...

# Run Go vet (optional)
vet:
	@echo "Running go vet..."
	go vet ./...

.PHONY: all build clean deps fmt vet

