package proto

import (
	"testing"
)

func TestTag_IsUniqueByte(t *testing.T) {
	tags := []byte{
		TagClientHello,
		TagServerHello,
		TagEntry,
		TagRendezvous,
		TagTunnelDatagram,
		TagTunnelStream,
		TagPing,
		TagPong,
		TagAck,
	}

	counts := map[byte]int{}

	for _, tag := range tags {
		counts[tag]++
	}

	for tag, count := range counts {
		if count > 1 {
			t.Errorf("tag value 0x%02x is used %d times", tag, count)
		}
	}
}
