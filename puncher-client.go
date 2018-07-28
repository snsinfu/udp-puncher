package main

import (
	"errors"
	"log"
	"net"
	"os"
	"time"

	"github.com/snsinfu/udp-puncher/mac"
)

const (
	bufferSize = 1472
)

func main() {
	if err := start(); err != nil {
		log.Fatal("error: ", err)
	}
}

func start() error {
	if len(os.Args) != 3 {
		return errors.New("invalid command-line usage")
	}

	server := os.Args[1]
	site := os.Args[2]
	key := mac.Key(os.Getenv("PUNCHER_KEY"))

	// Login
	serverAddr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		return err
	}

	conn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	myAddr := conn.LocalAddr().(*net.UDPAddr)
	nonce := time.Now().Unix() * 10

	login := key.Sign([]byte(site), nonce)
	if _, err := conn.Write(login.Encode()); err != nil {
		return err
	}

	buf := make([]byte, bufferSize)

	n, err := conn.Read(buf)
	if err != nil {
		return err
	}

	ack, err := mac.Decode(buf[:n])
	if err != nil {
		return err
	}

	if !key.Verify(ack) || ack.Nonce <= nonce {
		return errors.New("invalid server response")
	}
	nonce = ack.Nonce

	// Pairing
	n, err = conn.Read(buf)
	if err != nil {
		return err
	}

	pairing, err := mac.Decode(buf[:n])
	if err != nil {
		return err
	}

	if !key.Verify(pairing) || pairing.Nonce <= nonce {
		return errors.New("cannot verify server response")
	}

	peerAddr, err := net.ResolveUDPAddr("udp", string(pairing.Body))
	if err != nil {
		return err
	}

	log.Printf("I am %s", myAddr)
	log.Printf("Peer is %s", peerAddr)

	// Switch connection for hole punching
	if err := conn.Close(); err != nil {
		return err
	}

	conn, err = net.ListenUDP("udp", myAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Hole punch
	ping := [1]byte{0x80}
	pong := [1]byte{0x81}

	punched := false
	punchCh := make(chan bool)

	go func() {
		ticker := time.NewTicker(time.Second)
		for {
			select {
			case <-ticker.C:
				conn.WriteToUDP(ping[:], peerAddr)

			case <-punchCh:
				conn.WriteToUDP(pong[:], peerAddr)
				log.Print("Sent pong")
				return
			}
		}
	}()

punchLoop:
	for {
		buf := [1]byte{}

		_, _, err = conn.ReadFromUDP(buf[:])
		if err != nil {
			return err
		}

		switch buf {
		case ping:
			if !punched {
				close(punchCh)
				punched = true
			}

		case pong:
			if !punched {
				close(punchCh)
				punched = true
			}
			break punchLoop

		default:
		}
	}

	// Communication
	go func() {
		time.Sleep(time.Second)
		conn.WriteToUDP([]byte("Hello"), peerAddr)
		conn.WriteToUDP([]byte("See you"), peerAddr)
	}()
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	for i := 0; i < 2; i++ {
		n, err := conn.Read(buf)
		if err != nil {
			return err
		}
		log.Printf("Got message %q", buf[:n])
	}

	time.Sleep(time.Second)

	return nil
}
