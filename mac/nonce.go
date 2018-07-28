package mac

import (
	"encoding/binary"
)

// nonceSize is the number of bytes a nonce value occupies in its encoding.
const nonceSize = 8

// encodeNonce encodes val as bytes.
func encodeNonce(val int64) []byte {
	buf := make([]byte, nonceSize)
	binary.BigEndian.PutUint64(buf, uint64(val))
	return buf
}

// decodeNonce decodes buf as bytes produced by encodeNonce. This function
// panics if buf is smaller than 8 bytes.
func decodeNonce(buf []byte) int64 {
	return int64(binary.BigEndian.Uint64(buf))
}
