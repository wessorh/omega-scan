.PHONY: all build clean test proto release release-linux release-windows

all: build

build:
	go build -o bin/omega-scan ./cmd/omega-scan

proto:
	protoc \
	  --go_out=. --go_opt=module=github.com/support-intelligence/omega-scan \
	  --go-grpc_out=. --go-grpc_opt=module=github.com/support-intelligence/omega-scan \
	  api/omega/v1/omega.proto

test:
	go test ./...

bench:
	go test -bench=. -benchmem ./internal/fingerprint/

clean:
	rm -rf bin/

# ── Release builds ────────────────────────────────────────────────────

RELEASE_DIR = bin/release
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS = -s -w -X main.version=$(VERSION)
RELEASE_FLAGS = CGO_ENABLED=0

release: release-linux release-windows
	@echo "Release $(VERSION) built in $(RELEASE_DIR)/"
	@file $(RELEASE_DIR)/*
	@ls -lh $(RELEASE_DIR)/

release-linux:
	@mkdir -p $(RELEASE_DIR)
	$(RELEASE_FLAGS) GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(RELEASE_DIR)/omega-scan-linux-amd64 ./cmd/omega-scan

release-windows:
	@mkdir -p $(RELEASE_DIR)
	$(RELEASE_FLAGS) GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(RELEASE_DIR)/omega-scan-windows-amd64.exe ./cmd/omega-scan
