GO?=go
CGO_ENABLED=0

.PHONY: all
all:
	$(GO) build \
		-ldflags "-w -s" \
		-trimpath \
		-o tcpwall \
		main.go
