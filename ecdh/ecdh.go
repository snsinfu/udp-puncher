package ecdh

import (
	"errors"
	"io"

	"golang.org/x/crypto/curve25519"
)

// ErrInvalidPublicKey is returned by ComputeSecret if the size of apublic key
// is not 32 octets.
var ErrInvalidPublicKey = errors.New("public key must be 32-octet long")

// PrivateKey is an ECDH private key.
type PrivateKey struct {
	key [32]byte
}

// New reads a new private key from a secure random source. It reads exactly 32
// octets from r.
func New(r io.Reader) (*PrivateKey, error) {
	var priv PrivateKey
	if _, err := io.ReadFull(r, priv.key[:]); err != nil {
		return nil, err
	}
	return &priv, nil
}

// Public returns the public key paired to priv.
func (priv *PrivateKey) Public() []byte {
	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &priv.key)
	return pub[:]
}

// ComputeSecret returns a 32-octet shared secret computed from our private key
// and peer's public key. It returns an error if and only if pub is not a valid
// public key.
func (priv *PrivateKey) ComputeSecret(pub []byte) ([]byte, error) {
	if len(pub) != 32 {
		return nil, ErrInvalidPublicKey
	}
	var pubKey [32]byte
	var secret [32]byte
	copy(pubKey[:], pub)
	curve25519.ScalarMult(&secret, &priv.key, &pubKey)
	return secret[:], nil
}
