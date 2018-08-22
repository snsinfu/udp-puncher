package proto

// Message tag values.
const (
	TagClientHello    = 0x00
	TagServerHello    = 0x01
	TagEntry          = 0x10
	TagRendezvous     = 0x11
	TagTunnelDatagram = 0x20
	TagTunnelStream   = 0x21
	TagPing           = 0x80
	TagPong           = 0x81
	TagAck            = 0x82
)

type ClientHello struct {
	Random     []byte `msgpack:"random"`
	ECDHPubkey []byte `msgpack:"ecdh_pubkey"`
	Cookie     []byte `msgpack:"cookie"`
}

type ServerHello struct {
	Random     []byte `msgpack:"salt"`
	ECDHPubkey []byte `msgpack:"ecdh_pubkey"`
	Signature  []byte `msgpack:"signature"`
}

type Entry struct {
	PairingCode string `msgpack:"pairing_code"`
}

type Rendezvous struct {
	Peer string `msgpack:"peer"`
	Salt []byte `msgpack:"salt"`
	Rank uint8  `msgpack:"rank"`
}
