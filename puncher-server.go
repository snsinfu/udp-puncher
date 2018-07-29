package main

import (
	"errors"
	"log"
	"net"
	"os"
)

const (
	bufferSize = 1472
)

func main() {
	if err := run(); err != nil {
		log.Print("error: ", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) != 2 {
		return errors.New("invalid usage")
	}

	addr, err := net.ResolveUDPAddr("udp", os.Args[1])
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	buf := make([]byte, bufferSize)
	waitingClients := map[string]*net.UDPAddr{}

	for {
		n, client, err := conn.ReadFromUDP(buf)
		if err != nil {
			return err
		}

		if _, err := conn.WriteToUDP([]byte("OK"), client); err != nil {
			return err
		}

		pairCode := string(buf[:n])

		waitingClient, ok := waitingClients[pairCode]
		if !ok {
			waitingClients[pairCode] = client
			log.Printf("%s waits on %q", client, pairCode)
		}

		if ok && waitingClient.String() != client.String() {
			log.Printf("Pairing %s and %s", waitingClient, client)
			conn.WriteToUDP([]byte(waitingClient.String()), client)
			conn.WriteToUDP([]byte(client.String()), waitingClient)
			delete(waitingClients, pairCode)
		}
	}
}
