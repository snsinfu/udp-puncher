package main

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/snsinfu/go-taskch"
	"github.com/vmihailenco/msgpack"
	"golang.org/x/crypto/ed25519"

	"github.com/snsinfu/udp-puncher/ecdh"
	"github.com/snsinfu/udp-puncher/hkdf"
	"github.com/snsinfu/udp-puncher/proto"
)

const (
	bufferSize = 512
)

var (
	serverPrivkey = []byte{
		0x3e, 0xd9, 0x1e, 0x48, 0x20, 0x94, 0xa1, 0xd4, 0xa4, 0xe7, 0x70, 0xb9,
		0xec, 0xa3, 0xd9, 0x9e, 0x06, 0x76, 0xa4, 0xed, 0x9c, 0x0a, 0x18, 0xcb,
		0x3f, 0xd5, 0x35, 0xf2, 0x02, 0x05, 0xe0, 0x95,
	}
	serverPubkey = []byte{
		0xbe, 0xc3, 0x92, 0x0f, 0xc7, 0xd7, 0xaa, 0x79, 0xae, 0x34, 0xd6, 0x36,
		0x24, 0x5f, 0x73, 0x62, 0x22, 0xcf, 0xb9, 0x94, 0x4c, 0x58, 0x2d, 0xc0,
		0x44, 0x2b, 0xe3, 0x1e, 0xc9, 0xed, 0x21, 0x6f,
	}
)

func main() {
	tasks := taskch.New()

	clientR, clientW := io.Pipe()
	serverR, serverW := io.Pipe()

	tasks.Go(func() error {
		return startServer(serverR, clientW)
	})

	tasks.Go(func() error {
		return startClient(clientR, serverW)
	})

	if err := tasks.Wait(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func startServer(r io.Reader, w io.Writer) error {
	buf := make([]byte, bufferSize)

	// C -> S: ClientHello
	var clientHello proto.ClientHello
	for {
		n, err := r.Read(buf)
		if err != nil {
			return err
		}

		if buf[0] == proto.TagClientHello {
			if err := msgpack.Unmarshal(buf[1:n], &clientHello); err != nil {
				return err
			}
			break
		}
	}

	// S -> C: ServerHello
	serverRandom := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, serverRandom); err != nil {
		return err
	}

	sessionRandom := append(serverRandom, clientHello.Random...)

	priv := ed25519.NewKeyFromSeed(serverPrivkey)
	signature := ed25519.Sign(priv, sessionRandom)

	dh, err := ecdh.New(rand.Reader)
	if err != nil {
		return err
	}

	body, err := msgpack.Marshal(proto.ServerHello{
		Random:     serverRandom,
		ECDHPubkey: dh.Public(),
		Signature:  signature,
	})
	if err != nil {
		return err
	}

	msg := append([]byte{proto.TagServerHello}, body...)
	if _, err := w.Write(msg); err != nil {
		return err
	}

	// Derive keys
	masterSecret, err := dh.ComputeSecret(clientHello.ECDHPubkey)
	if err != nil {
		return err
	}

	hk := hkdf.New(sha256.New, masterSecret, sessionRandom)
	serverKey := hk.DeriveKey(16, []byte("server key"))
	clientKey := hk.DeriveKey(16, []byte("client key"))

	fmt.Printf("[server] server key: %x\n", serverKey)
	fmt.Printf("[server] client key: %x\n", clientKey)

	return nil
}

func startClient(r io.Reader, w io.Writer) error {
	buf := make([]byte, bufferSize)

	// C -> S: ClientHello
	clientRandom := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, clientRandom); err != nil {
		return err
	}

	dh, err := ecdh.New(rand.Reader)
	if err != nil {
		return err
	}

	body, err := msgpack.Marshal(proto.ClientHello{
		Random:     clientRandom,
		ECDHPubkey: dh.Public(),
	})
	if err != nil {
		return err
	}

	msg := append([]byte{proto.TagClientHello}, body...)
	go w.Write(msg)

	// S -> C: ServerHello
	var serverHello proto.ServerHello
	for {
		n, err := r.Read(buf)
		if err != nil {
			return err
		}

		if buf[0] == proto.TagServerHello {
			if err := msgpack.Unmarshal(buf[1:n], &serverHello); err != nil {
				return err
			}
			break
		}
	}

	sessionRandom := append(serverHello.Random, clientRandom...)

	pub := ed25519.PublicKey(serverPubkey)
	if !ed25519.Verify(pub, sessionRandom, serverHello.Signature) {
		return errors.New("signature verification failed")
	}

	// Derive keys
	masterSecret, err := dh.ComputeSecret(serverHello.ECDHPubkey)
	if err != nil {
		return err
	}

	hk := hkdf.New(sha256.New, masterSecret, sessionRandom)
	serverKey := hk.DeriveKey(16, []byte("server key"))
	clientKey := hk.DeriveKey(16, []byte("client key"))

	fmt.Printf("[client] server key: %x\n", serverKey)
	fmt.Printf("[client] client key: %x\n", clientKey)

	return nil
}
