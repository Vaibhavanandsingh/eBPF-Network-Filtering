GO ?= go
CLANG ?= clang

.PHONY: all generate build clean

all: build

generate:
	$(GO) generate ./cmd/drop ./cmd/process-filter

build: generate
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -o bin/drop ./cmd/drop
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -o bin/process-filter ./cmd/process-filter

clean:
	rm -f bin/drop bin/process-filter cmd/drop/drop_bpf*.go cmd/process-filter/process_filter_bpf*.go cmd/drop/*.o cmd/process-filter/*.o
