package main

import (
	"errors"
	"log"
	"net"
	"os"

	"github.com/snsinfu/udp-puncher/mac"
)

const bufferSize = 1472

type rendezvousSite struct {
	key     mac.Key
	nonce   int64
	clients map[string]*net.UDPAddr
}

func main() {
	if err := start(); err != nil {
		log.Fatal("error: ", err)
	}
}

func start() error {
	if len(os.Args) != 2 {
		return errors.New("invalid command-line usage")
	}

	addr, err := net.ResolveUDPAddr("udp", os.Args[1])
	if err != nil {
		return err
	}

	sites := map[string]*rendezvousSite{
		"/foo": &rendezvousSite{
			key:     mac.Key("fookey"),
			clients: map[string]*net.UDPAddr{},
		},
		"/bar": &rendezvousSite{
			key:     mac.Key("barkey"),
			clients: map[string]*net.UDPAddr{},
		},
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	buf := make([]byte, bufferSize)

	for {
		n, client, err := conn.ReadFromUDP(buf)
		if err != nil {
			return err
		}

		m, err := mac.Decode(buf[:n])
		if err != nil {
			log.Printf("%s: Sends bogus packet: %s", client, err)
			continue
		}

		name := string(m.Body)
		site, ok := sites[name]
		if !ok {
			log.Printf("%s: Requests nonexistent site %q", client, name)
			continue
		}

		if !site.key.Verify(m) || m.Nonce <= site.nonce {
			log.Printf("%s: Sends invalid message", client)
			continue
		}

		log.Printf("%s: Login to %q", client, name)

		site.clients[client.String()] = client
		site.nonce = m.Nonce

		log.Printf("%d clients in %q", len(site.clients), name)

		if len(site.clients) == 2 {
			addrs := []*net.UDPAddr{}
			for _, addr := range site.clients {
				addrs = append(addrs, addr)
			}
			site.clients = map[string]*net.UDPAddr{}

			log.Printf("Pairing %s and %s", addrs[0], addrs[1])

			nonce := site.nonce + 1

			m0 := site.key.Sign([]byte(addrs[1].String()), nonce)
			conn.WriteToUDP(m0.Encode(), addrs[0])

			m1 := site.key.Sign([]byte(addrs[0].String()), nonce)
			conn.WriteToUDP(m1.Encode(), addrs[1])
		}
	}

	return nil
}
