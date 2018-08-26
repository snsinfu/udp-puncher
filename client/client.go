package client

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net"

	"github.com/vmihailenco/msgpack"
	"golang.org/x/crypto/ed25519"

	"github.com/snsinfu/udp-puncher/ecdh"
	"github.com/snsinfu/udp-puncher/hkdf"
	"github.com/snsinfu/udp-puncher/proto"
)

const (
	serverAddress    = "127.0.0.1:1111"
	serverSignPubkey = "09be80e864e8bf384ebf8d07898a25e9911fda6453a4157444416c39ef1cf43f"
	bufferSize       = 512
	clientSecret     = "c2281a5f8681c85623f750a3ec7223d390b68740fe72e6eb12d2733be90d6a27"
	pairingName      = "mosh"
)

func Start() error {
	log.Print("Dial")

	addr, err := net.ResolveUDPAddr("udp", serverAddress)
	if err != nil {
		return err
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	// C -> S: ClientHello
	dh, err := ecdh.New(rand.Reader)
	if err != nil {
		return err
	}

	clientRandom := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, clientRandom); err != nil {
		return err
	}

	var cookie []byte
retryHello:
	msg, err := msgpack.Marshal(proto.ClientHello{
		Random:     clientRandom,
		ECDHPubkey: dh.Public(),
		Cookie:     cookie,
	})
	if err != nil {
		return err
	}

	msg = append([]byte{proto.TagClientHello}, msg...)

	if _, err := conn.Write(msg); err != nil {
		return err
	}

	log.Printf("send ClientHello: cookie = %x", cookie)

	// S -> C: Cookie or ServerHello
	buf := make([]byte, bufferSize)
	var serverHello proto.ServerHello

	for {
		n, err := conn.Read(buf)
		if err != nil {
			return err
		}

		if buf[0] == proto.TagCookie {
			var c proto.Cookie
			if err := msgpack.Unmarshal(buf[1:n], &c); err != nil {
				continue
			}
			cookie = c.Cookie

			log.Printf("recv Cookie: cookie = %x", c.Cookie)

			goto retryHello
		}

		if buf[0] == proto.TagServerHello {
			log.Print("ServerHello")
			if err := msgpack.Unmarshal(buf[1:n], &serverHello); err != nil {
				continue
			}
			break
		}
	}

	log.Printf("recv ServerHello")

	salt := append(serverHello.Random, clientRandom...)
	signPubkey := ed25519.PublicKey(mustDecodeHex(serverSignPubkey))
	if !ed25519.Verify(signPubkey, salt, serverHello.Signature) {
		return errors.New("server verification")
	}

	log.Printf("good signature")

	// Key derivation
	masterSecret, err := dh.ComputeSecret(serverHello.ECDHPubkey)
	if err != nil {
		return err
	}

	log.Printf("master secret = %x", masterSecret)

	hk := hkdf.New(sha256.New, masterSecret, salt)
	serverKey := hk.DeriveKey(16, []byte("server key"))
	clientKey := hk.DeriveKey(16, []byte("client key"))
	serverIV := hk.DeriveKey(12, []byte("server iv"))
	clientIV := hk.DeriveKey(12, []byte("client iv"))

	serverCipher, err := proto.NewCipher(serverKey, serverIV)
	if err != nil {
		return err
	}

	clientCipher, err := proto.NewCipher(clientKey, clientIV)
	if err != nil {
		return err
	}

	// C -> S: Entry
	mac := hmac.New(sha256.New, mustDecodeHex(clientSecret))
	mac.Write([]byte(pairingName))
	pairingCode := mac.Sum(nil)

	msg, err = msgpack.Marshal(proto.Entry{
		PairingCode: pairingCode,
	})
	if err != nil {
		return err
	}

	msg = clientCipher.Seal(msg, proto.TagEntry)

	if _, err := conn.Write(msg); err != nil {
		return err
	}

	log.Printf("send Entry: pairingCode = %x", pairingCode)

	// S -> C: Ack
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return err
		}

		_, tag, err := serverCipher.Open(buf[:n])
		if err != nil {
			continue
		}

		if tag == proto.TagAck {
			break
		}
	}

	log.Printf("recv Ack")

	// S -> C: Ping
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return err
		}

		_, tag, err := serverCipher.Open(buf[:n])
		if err != nil {
			continue
		}

		if tag == proto.TagPing {
			break
		}
	}

	log.Printf("recv Ping")

	// C -> S: Pong
	msg = clientCipher.Seal(nil, proto.TagPong)

	if _, err := conn.Write(msg); err != nil {
		return err
	}

	log.Printf("send Pong")
	log.Printf("Done")

	return nil
}

func mustDecodeHex(s string) []byte {
	data, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return data
}
