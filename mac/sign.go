package mac

import (
	"crypto/hmac"
	"crypto/sha256"
)

// macSize is the length of MAC in bytes.
const macSize = 32

// Key is a HMAC signing key.
type Key []byte

// Sign signs data with key and given nonce value.
func (key Key) Sign(data []byte, nonce int64) Message {
	mac := hmac.New(sha256.New, key)
	mac.Write(encodeNonce(nonce))
	mac.Write(data)

	return Message{
		MAC:   mac.Sum(nil),
		Nonce: nonce,
		Body:  data,
	}
}

// Verify verifies a signed message with key.
func (key Key) Verify(m Message) bool {
	return hmac.Equal(m.MAC, key.Sign(m.Body, m.Nonce).MAC)
}
