.PHONY: all build clean test proto

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
