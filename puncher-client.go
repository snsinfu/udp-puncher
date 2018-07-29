package main

import (
	"errors"
	"log"
	"net"
	"os"
	"time"
)

const (
	bufferSize   = 1472
	ackTimeout   = 2 * time.Second
	pingInterval = time.Second
)

func main() {
	if err := run(); err != nil {
		log.Print("error: ", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) != 3 {
		return errors.New("invalid usage")
	}

	server, err := net.ResolveUDPAddr("udp", os.Args[1])
	if err != nil {
		return err
	}

	pairCode := os.Args[2]

	// Rendezvous
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return err
	}
	defer conn.Close()

	buf := make([]byte, bufferSize)
	peer := (*net.UDPAddr)(nil)

loginLoop:
	for {
		if _, err := conn.WriteToUDP([]byte(pairCode), server); err != nil {
			return err
		}

		conn.SetReadDeadline(time.Now().Add(ackTimeout))
		for {
			n, sender, err := conn.ReadFromUDP(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue loginLoop
				}
				return err
			}

			if !equal(sender, server) {
				continue
			}

			if string(buf[:n]) == "OK" {
				break loginLoop
			}
		}
	}
	conn.SetReadDeadline(time.Time{})

	for {
		n, sender, err := conn.ReadFromUDP(buf)
		if err != nil {
			return err
		}

		if !equal(sender, server) {
			continue
		}

		peer, err = net.ResolveUDPAddr("udp", string(buf[:n]))
		if err != nil {
			return err
		}

		break
	}

	// Hole-punch
	ping := [1]byte{0x80}
	pong := [1]byte{0x81}

	punched := false
	punchCh := make(chan bool)

	go func() {
		ticker := time.NewTicker(pingInterval)
		for {
			select {
			case <-ticker.C:
				conn.WriteToUDP(ping[:], peer)
				log.Print("Sent ping")

			case <-punchCh:
				conn.WriteToUDP(pong[:], peer)
				log.Print("Sent pong")
				return
			}
		}
	}()

	for {
		n, sender, err := conn.ReadFromUDP(buf)
		if err != nil {
			return err
		}

		if !equal(sender, peer) {
			continue
		}

		if !punched {
			punched = true
			close(punchCh)
		}

		if n == 1 && buf[0] == pong[0] {
			log.Print("Got pong")
			break
		}
	}

	//
	join := make(chan bool)

	go func() {
		buf := make([]byte, 1472)

		for {
			n, sender, err := conn.ReadFromUDP(buf)
			if err != nil {
				break
			}

			if !equal(sender, peer) {
				continue
			}

			if _, err := os.Stdout.Write(buf[:n]); err != nil {
				break
			}
		}

		join <- true
	}()

	go func() {
		buf := make([]byte, 1472)

		for {
			n, err := os.Stdin.Read(buf)
			if err != nil {
				break
			}

			if _, err := conn.WriteToUDP(buf[:n], peer); err != nil {
				break
			}
		}

		join <- true
	}()

	<-join

	return nil
}

func equal(a, b *net.UDPAddr) bool {
	return a.Port == b.Port && a.IP.Equal(b.IP) && a.Zone == b.Zone
}
