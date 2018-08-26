package proto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
)

const (
	counterSize     = 8
	headerSize      = counterSize + 1
	messageOverhead = headerSize + 16
	nonceSize       = 12
)

// ErrInvalidIV is returned by NewCipher if the size of an IV is invalid.
var ErrInvalidIV = errors.New("invalid IV size")

// ErrInvalidMessage is returned by Open if the format of a message is invalid.
var ErrInvalidMessage = errors.New("invalid message format")

// ErrReplayAttack is returned by Open if the counter value of a message is
// not greater than that of a previously decrypted one.
var ErrReplayAttack = errors.New("message is replayed")

// Cipher encrypts or decrypts a series of messages using AES-GCM and
// monotonically increasing counter.
type Cipher struct {
	gcm     cipher.AEAD
	iv      []byte
	counter uint64
}

// NewCipher creates a Cipher with given AES key and IV. The IV is used to
// derive a nonce for each message and must be 12 bytes long.
func NewCipher(key, iv []byte) (*Cipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(iv) != nonceSize {
		return nil, ErrInvalidIV
	}

	cipher := &Cipher{
		gcm:     gcm,
		iv:      make([]byte, nonceSize),
		counter: 0,
	}
	copy(cipher.iv, iv)

	return cipher, nil
}

// Seal encrypts data and prepends given tag and counter values as a header in
// big endian format. The header is authenticated by GMAC.
func (c *Cipher) Seal(data []byte, tag byte) []byte {
	c.counter++
	if c.counter == 0 {
		panic("counter wraparound")
	}

	var counterCode [counterSize]byte
	binary.LittleEndian.PutUint64(counterCode[:], c.counter)

	buf := make([]byte, len(data)+messageOverhead)
	header := buf[:headerSize]
	header[0] = tag
	copy(header[1:], counterCode[:])

	var nonce [nonceSize]byte
	copy(nonce[:], c.iv)
	for i := range counterCode {
		nonce[i] ^= counterCode[i]
	}

	return c.gcm.Seal(header, nonce[:], data, header)
}

// Open decodes and decrypts a message created by Seal.
func (c *Cipher) Open(msg []byte) ([]byte, byte, error) {
	if len(msg) < messageOverhead {
		return nil, 0, ErrInvalidMessage
	}

	header := msg[:headerSize]
	tag := header[0]
	counterCode := header[1:]

	counter := binary.LittleEndian.Uint64(counterCode)
	if counter <= c.counter {
		return nil, 0, ErrReplayAttack
	}
	c.counter = counter

	var nonce [nonceSize]byte
	copy(nonce[:], c.iv)
	for i := range counterCode {
		nonce[i] ^= counterCode[i]
	}

	data, err := c.gcm.Open(nil, nonce[:], msg[headerSize:], header)
	if err != nil {
		return nil, 0, err
	}

	return data, tag, nil
}

// AttachTag returns a plaintext message holding given data and tag.
func AttachTag(data []byte, tag byte) []byte {
	return append([]byte{tag}, data...)
}

// DetachTag returns data and tag encoded in msg. It returns ErrInvalidMessage
// if msg is empty. This function can also be used to inspect the tag of a
// message created by Cipher.
func DetachTag(msg []byte) ([]byte, byte, error) {
	if len(msg) == 0 {
		return nil, 0, ErrInvalidMessage
	}
	return msg[1:], msg[0], nil
}
