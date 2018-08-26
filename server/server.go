package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"bytes"
	"encoding/hex"
	"io"
	"log"
	"net"
	"time"

	"github.com/vmihailenco/msgpack"
	"golang.org/x/crypto/ed25519"

	"github.com/snsinfu/udp-puncher/ecdh"
	"github.com/snsinfu/udp-puncher/hkdf"
	"github.com/snsinfu/udp-puncher/proto"
)

const (
	serverAddress     = "127.0.0.1:1111"
	serverSignPrivkey = "e3db0b25d5657a6a35c734755354ab66512653b543dbeaa0f990fa4d24fff1e9"
	serverSignPubkey  = "09be80e864e8bf384ebf8d07898a25e9911fda6453a4157444416c39ef1cf43f"
	bufferSize        = 512
)

type session struct {
	conn   *net.UDPConn
	client *net.UDPAddr
	recv   chan []byte
}

func Start() error {
	addr, err := net.ResolveUDPAddr("udp", serverAddress)
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	buf := make([]byte, bufferSize)
	sessions := map[string]*session{}
	cookieKey := make([]byte, 8)
	cookieTimer := time.Tick(60*time.Second)

	for {
		n, client, err := conn.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		clientID := client.String()

		sess, ok := sessions[clientID]
		if !ok {
			data, tag, _ := proto.DetachTag(buf[:n])
			if tag != proto.TagClientHello {
				continue
			}

			var hello proto.ClientHello
			if err := msgpack.Unmarshal(data, &hello); err != nil {
				continue
			}

			select {
			case <-cookieTimer:
				if _, err := io.ReadFull(rand.Reader, cookieKey); err != nil {
					return err
				}
			default:
			}

			mac := hmac.New(sha256.New, cookieKey)
			mac.Write([]byte(clientID))
			cookie := mac.Sum(nil)

			if !bytes.Equal(hello.Cookie, cookie) {
				msg, err := msgpack.Marshal(proto.Cookie{Cookie: cookie})
				if err != nil {
					return err
				}

				msg = proto.AttachTag(msg, proto.TagCookie)
				if _, err := conn.WriteToUDP(msg, client); err != nil {
					return err
				}

				continue
			}

			sess = &session{
				conn:   conn,
				client: client,
				recv:   make(chan []byte),
			}
			sessions[clientID] = sess

			go func() {
				defer delete(sessions, clientID)
				defer close(sess.recv)

				if err := sess.main(); err != nil {
					log.Printf("[%s] error:", clientID, err)
				}
			}()
		}

		sess.recv <- buf[:n]
	}

	return nil
}

// C -> S: ClientHello
// S -> C: ServerHello
// C -> S: Entry
// S -> C: Ack
// S -> C: Ping
// C -> S: Pong
// S -> C: Rendezvous
// C -> S: Ack

func (sess *session) main() error {
	log.Printf("[%s] session start", sess.client)

	// C -> S: ClientHello
	var clientHello proto.ClientHello

	for {
		msg := <-sess.recv

		data, tag, _ := proto.DetachTag(msg)
		if tag != proto.TagClientHello {
			continue
		}

		if err := msgpack.Unmarshal(data, &clientHello); err != nil {
			return err
		}

		break
	}

	log.Printf("[%s] recv ClientHello", sess.client)

	// S -> C: ServerHello
	dh, err := ecdh.New(rand.Reader)
	if err != nil {
		return err
	}

	serverRandom := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, serverRandom); err != nil {
		return err
	}

	salt := append(serverRandom, clientHello.Random...)
	signature := ed25519.Sign(ed25519.NewKeyFromSeed(mustDecodeHex(serverSignPrivkey)), salt)

	msg, err := msgpack.Marshal(proto.ServerHello{
		Random:     serverRandom,
		ECDHPubkey: dh.Public(),
		SignPubkey: mustDecodeHex(serverSignPubkey),
		Signature:  signature,
	})
	if err != nil {
		return err
	}

	msg = append([]byte{proto.TagServerHello}, msg...)

	if _, err := sess.conn.WriteToUDP(msg, sess.client); err != nil {
		return err
	}

	log.Printf("[%s] send ServerHello", sess.client)

	// Key derivation
	masterSecret, err := dh.ComputeSecret(clientHello.ECDHPubkey)
	if err != nil {
		return err
	}

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

	log.Printf("[%s] master secret = %x", sess.client, masterSecret)

	// C -> S: Entry
	var entry proto.Entry

	for {
		msg, tag, err := clientCipher.Open(<-sess.recv)
		if err != nil {
			continue
		}

		if tag != proto.TagEntry {
			continue
		}

		if err := msgpack.Unmarshal(msg, &entry); err != nil {
			return err
		}

		break
	}

	log.Printf("[%s] recv Entry: pairingCode = %x", sess.client, entry.PairingCode)

	// S -> C: Ack
	msg = serverCipher.Seal(nil, proto.TagAck)

	if _, err := sess.conn.WriteToUDP(msg, sess.client); err != nil {
		return err
	}

	log.Printf("[%s] send Ack", sess.client)

	// S -> C: Ping
	msg = serverCipher.Seal(nil, proto.TagPing)

	if _, err := sess.conn.WriteToUDP(msg, sess.client); err != nil {
		return err
	}

	log.Printf("[%s] send Ping", sess.client)

	// C -> S: Pong
	for {
		_, tag, err := clientCipher.Open(<-sess.recv)
		if err != nil {
			continue
		}

		if tag != proto.TagPong {
			continue
		}

		break
	}

	log.Printf("[%s] recv Pong", sess.client)

	log.Printf("[%s] Done", sess.client)

	return nil
}

func mustDecodeHex(s string) []byte {
	data, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return data
}
