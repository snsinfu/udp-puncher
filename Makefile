PRODUCTS = puncher-client puncher-server

.PHONY: all clean

all: $(PRODUCTS)
	@:

clean:
	rm -f $(PRODUCTS)

puncher-client: puncher-client.go
	go build -o $@ puncher-client.go

puncher-server: puncher-server.go
	go build -o $@ puncher-server.go
