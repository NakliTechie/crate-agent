# SPDX-License-Identifier: AGPL-3.0-or-later
# Cross-compile crate-agent to darwin amd64+arm64 + linux amd64+arm64.
# Static linkage (CGO_ENABLED=0) so the binary has no runtime dependencies.

BINARY := crate-agent
VERSION ?= 0.0.0-m0
LDFLAGS := -X main.version=$(VERSION)
DIST := dist

.PHONY: all clean build help

all: clean $(DIST)/$(BINARY)-darwin-amd64 $(DIST)/$(BINARY)-darwin-arm64 $(DIST)/$(BINARY)-linux-amd64 $(DIST)/$(BINARY)-linux-arm64

$(DIST)/$(BINARY)-darwin-amd64:
	@mkdir -p $(DIST)
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $@ .

$(DIST)/$(BINARY)-darwin-arm64:
	@mkdir -p $(DIST)
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $@ .

$(DIST)/$(BINARY)-linux-amd64:
	@mkdir -p $(DIST)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $@ .

$(DIST)/$(BINARY)-linux-arm64:
	@mkdir -p $(DIST)
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $@ .

build:
	go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(BINARY) .

clean:
	rm -rf $(DIST)

help:
	@echo "make all   — cross-compile darwin + linux (amd64 + arm64 each)"
	@echo "make build — build for current host only"
	@echo "make clean — remove dist/"
