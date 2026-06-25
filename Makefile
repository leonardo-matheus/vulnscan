.PHONY: build build-all clean test lint install

VERSION := $(shell git describe --tags --always 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X github.com/leonardo-matheus/vulnscan/internal/config.Version=$(VERSION) -X github.com/leonardo-matheus/vulnscan/internal/config.Commit=$(COMMIT) -X github.com/leonardo-matheus/vulnscan/internal/config.Date=$(DATE)

build:
	go build -ldflags "$(LDFLAGS)" -o vulngate.exe .

build-linux:
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o vulngate-linux-amd64 .
	GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o vulngate-linux-arm64 .

build-darwin:
	GOOS=darwin GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o vulngate-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o vulngate-darwin-arm64 .

build-windows:
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o vulngate.exe .

build-all: build-linux build-darwin build-windows

test:
	go test -v -race ./...

lint:
	go vet ./...

clean:
	rm -f vulngate vulngate.exe vulngate-linux-* vulngate-darwin-*

install: build
	./vulngate.exe install
