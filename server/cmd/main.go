package main

import (
	"fmt"
	"log"

	"github.com/docopt/docopt-go"
	"github.com/snsinfu/udp-puncher/server"
)

const usage = `
Usage: puncher-server

Options:
  -h, --help  Print this message and exit
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

	return server.Start()
}
