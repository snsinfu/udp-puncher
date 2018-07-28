package mac

import (
	"errors"
)

// minMessageSize is the minimum size of a message in bytes.
const minMessageSize = macSize + nonceSize

// ErrMalformedMessage is returned when bytes do not encode a Message.
var ErrMalformedMessage = errors.New("malformed message")

// Message is an HMAC-signed binary message with 64-bit integral nonce.
type Message struct {
	MAC   []byte
	Nonce int64
	Body  []byte
}

// Encode encodes a Message as binary bytes.
func (m Message) Encode() []byte {
	return append(append(m.MAC, encodeNonce(m.Nonce)...), m.Body...)
}

// Decode decodes binary bytes encoding a Message.
func Decode(msg []byte) (Message, error) {
	m := Message{}

	if len(msg) < minMessageSize {
		return m, ErrMalformedMessage
	}

	m.MAC = msg[:macSize]
	m.Nonce = decodeNonce(msg[macSize : macSize+nonceSize])
	m.Body = msg[macSize+nonceSize:]

	return m, nil
}
