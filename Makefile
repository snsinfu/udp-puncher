PRODUCTS = puncher puncher-server
ARTIFACTS = $(PRODUCTS) _depends.ok

.PHONY: all test fmt clean

all: $(PRODUCTS)
	@:

test:
	go test ./...

fmt:
	go fmt ./...

clean:
	rm -f $(ARTIFACTS)

_depends.ok:
	go get ./...
	@touch $@

puncher: client/cmd/main.go _depends.ok
	go build -o $@ ./client/cmd

puncher-server: server/cmd/main.go _depends.ok
	go build -o $@ ./server/cmd
