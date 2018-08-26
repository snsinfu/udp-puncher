package main

import (
	"fmt"
	"log"

	"github.com/docopt/docopt-go"
	"github.com/snsinfu/udp-puncher/client"
)

const usage = `
Usage: puncher [options] <site>

Options:
  -C, --connect <addr>  Connect to <addr>
  -L, --listen <addr>   Listen on <addr>
  -h, --help            Print this message and exit

Environments:
  PUNCHER_KEY  Client shared secret in hexadecimal format
`

func main() {
	if err := run(); err != nil {
		log.Fatal("error: ", err)
	}
}

func run() error {
	opts, err := docopt.ParseDoc(usage)
	if err != nil {
		return err
	}

	for name, value := range opts {
		fmt.Printf("%s\t%v\n", name, value)
	}

	return client.Start()
}
