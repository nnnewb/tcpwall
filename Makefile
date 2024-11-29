GO?=go
CGO_ENABLED=0

DEFINES=-X 'main.VERSION=$(shell git describe --tags)' \
	-X 'main.REVISION=$(shell git rev-parse --short=7 HEAD)' \
	-X 'main.BUILD=$(shell date --rfc-3339=seconds)'

.PHONY: all
all:
	$(GO) build \
		-ldflags "-w -s $(DEFINES)" \
		-trimpath \
		-o tcpwall \
		main.go
