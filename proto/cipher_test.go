package proto

import (
	"bytes"
	"testing"
)

func TestNewCipher_CreatesCipher(t *testing.T) {
	key := []byte("0123456789abcdef")
	iv := []byte("0123456789ab")

	cipher, err := NewCipher(key, iv)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if cipher == nil {
		t.Fatalf("cipher is nil")
	}

	// Whitebox tests
	if !bytes.Equal(cipher.iv, iv) {
		t.Errorf("IV is not correctly set: got %x, want %x", cipher.iv, iv)
	}

	nonceSize := cipher.gcm.NonceSize()
	if len(iv) != nonceSize {
		t.Errorf("inconsistent IV size: got %d, want %d", len(iv), nonceSize)
	}

	if cipher.counter != 0 {
		t.Errorf("initial counter value: got %d, want 0", cipher.counter)
	}
}

func TestNewCipher_RejectsInvalidIV(t *testing.T) {
	key := []byte("0123456789abcdef")

	// Zero
	cipher, err := NewCipher(key, []byte{})
	if err == nil {
		t.Errorf("unexpected success: cipher = %v", cipher)
	}

	// Too short 88-bit IV
	cipher, err = NewCipher(key, []byte("0123456789a"))
	if err == nil {
		t.Errorf("unexpected success: cipher = %v", cipher)
	}

	// Valid 96-bit IV
	_, err = NewCipher(key, []byte("0123456789ab"))
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	// Too long 104-bit IV
	cipher, err = NewCipher(key, []byte("0123456789abc"))
	if err == nil {
		t.Errorf("unexpected success: cipher = %v", cipher)
	}
}

func TestCipher_Open_RejectsInvalidMessage(t *testing.T) {
	key := []byte("0123456789abcdef")
	iv := []byte("0123456789ab")

	opener, err := NewCipher(key, iv)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	// Empty
	_, _, err = opener.Open([]byte{})
	if err != ErrInvalidMessage {
		t.Errorf("unexpected condition: err = %v", err)
	}

	// Short
	_, _, err = opener.Open([]byte{0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01})
	if err != ErrInvalidMessage {
		t.Errorf("unexpected condition: err = %v", err)
	}
}

func TestCipher_Open_DetectsReplayAttack(t *testing.T) {
	key := []byte("0123456789abcdef")
	iv := []byte("0123456789ab")

	sealer, err := NewCipher(key, iv)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	opener, err := NewCipher(key, iv)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	msg1 := sealer.Seal([]byte("Hello"), 1)
	msg2 := sealer.Seal([]byte("See you"), 2)

	// First message
	_, _, err = opener.Open(msg1)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	// Replay
	_, _, err = opener.Open(msg1)
	if err != ErrReplayAttack {
		t.Errorf("unexpected condition: err = %v", err)
	}

	// Second message
	_, _, err = opener.Open(msg2)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	// Replay
	_, _, err = opener.Open(msg2)
	if err != ErrReplayAttack {
		t.Errorf("unexpected condition: err = %v", err)
	}

	// Replay
	_, _, err = opener.Open(msg1)
	if err != ErrReplayAttack {
		t.Errorf("unexpected condition: err = %v", err)
	}
}

func TestCipher_Open_DetectsTagTampering(t *testing.T) {
	key := []byte("0123456789abcdef")
	iv := []byte("0123456789ab")

	sealer, err := NewCipher(key, iv)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	opener, err := NewCipher(key, iv)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	// Tamper with a tag value [0..0]
	msg := sealer.Seal([]byte("Hello"), 0x12)
	msg[0] = 0x34

	_, _, err = opener.Open(msg)
	if err == nil {
		t.Error("unexpected success")
	}
}

func TestCipher_Open_DetectsCounterTampering(t *testing.T) {
	key := []byte("0123456789abcdef")
	iv := []byte("0123456789ab")

	sealer, err := NewCipher(key, iv)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	opener, err := NewCipher(key, iv)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	// Tamper with a counter value [1..8]
	msg := sealer.Seal([]byte("Hello"), 0x12)
	msg[8] = 2

	_, _, err = opener.Open(msg)
	if err == nil {
		t.Error("unexpected success")
	}
}

func TestCipher_Open_DetectsCiphertextTampering(t *testing.T) {
	key := []byte("0123456789abcdef")
	iv := []byte("0123456789ab")

	sealer, err := NewCipher(key, iv)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	opener, err := NewCipher(key, iv)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	// Tamper with a ciphertext
	msg := sealer.Seal([]byte("Hello"), 0x12)
	msg[9] ^= 0xcc

	_, _, err = opener.Open(msg)
	if err == nil {
		t.Error("unexpected success")
	}
}

func TestCipher_Roundtrip(t *testing.T) {
	key := []byte("0123456789abcdefghijklmnopqrstuv")
	iv := []byte("0123456789ab")

	sealer, err := NewCipher(key, iv)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	opener, err := NewCipher(key, iv)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	inputs := []struct {
		tag       byte
		plaintext []byte
	}{
		{0x12, []byte("The quick brown fox jumps over the lazy dog")},
		{0x34, []byte("Lorem ipsum dolor sit amet")},
		{0x56, []byte("Etaoin shrdlu")},
	}

	for _, input := range inputs {
		message := sealer.Seal(input.plaintext, input.tag)

		plaintext, tag, err := opener.Open(message)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}

		if !bytes.Equal(plaintext, input.plaintext) {
			t.Errorf("unexpected plaintext: got %q, want %q", plaintext, input.plaintext)
		}

		if tag != input.tag {
			t.Errorf("unexpected tag: got %x, want %x", tag, input.tag)
		}
	}
}

func TestCipher_Examples(t *testing.T) {
	inputs := []struct {
		tag       byte
		plaintext []byte
		key       []byte
		iv        []byte
		message   []byte
	}{
		{
			tag:       0x12,
			plaintext: []byte("Lorem ipsum dolor sit amet"),
			key:       []byte("764984c0596f0b0b83cc7134b01da2ce"),
			iv:        []byte("b8142da49d5f"),
			message: []byte{
				0x12, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x47, 0xd9, 0xbc,
				0x7e, 0xfe, 0x90, 0x6a, 0xbe, 0x33, 0xaf, 0xb6, 0x87, 0xd1, 0xdf, 0x0f,
				0xf0, 0x88, 0x70, 0x99, 0xe2, 0x18, 0xdb, 0x72, 0xe4, 0x09, 0xef, 0xba,
				0x58, 0xb8, 0xe1, 0xb9, 0x8c, 0xe8, 0x7a, 0xe1, 0x09, 0xf3, 0x7e, 0x0d,
				0x17, 0xb2, 0xa5,
			},
		},
		{
			tag:       0x34,
			plaintext: []byte("The quick brown fox jumps over the lazy dog"),
			key:       []byte("f93cc9efed8278aa"),
			iv:        []byte("c4ad3e07ecd5"),
			message: []byte{
				0x34, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x7e, 0x66,
				0x66, 0x5c, 0x72, 0x86, 0xb8, 0xfb, 0x28, 0xd4, 0x38, 0xb9, 0x82, 0x38,
				0xfd, 0xff, 0xda, 0xb9, 0xff, 0xc9, 0x70, 0xf4, 0x23, 0x1e, 0xc3, 0x28,
				0x46, 0x72, 0xad, 0xe5, 0x7d, 0x28, 0x8b, 0xf3, 0xc0, 0x95, 0x85, 0x84,
				0xb7, 0x7a, 0x15, 0xf6, 0xaa, 0x69, 0xa5, 0x0c, 0x15, 0x9c, 0x1e, 0x80,
				0xec, 0x88, 0x5a, 0xcf, 0x26, 0x2f, 0x42, 0x72,
			},
		},
	}

	// Seal
	for _, input := range inputs {
		sealer, err := NewCipher(input.key, input.iv)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}

		message := sealer.Seal(input.plaintext, input.tag)

		if !bytes.Equal(message, input.message) {
			t.Errorf("unexpected message: got %x, want %x", message, input.message)
		}
	}

	// Open
	for _, input := range inputs {
		opener, err := NewCipher(input.key, input.iv)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}

		plaintext, tag, err := opener.Open(input.message)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}

		if !bytes.Equal(plaintext, input.plaintext) {
			t.Errorf("unexpected plaintext: got %q, want %q", plaintext, input.plaintext)
		}

		if tag != input.tag {
			t.Errorf("unexpected plaintext: got %d, want %d", tag, input.tag)
		}
	}
}

func TestAttachTag_PrependsTagToData(t *testing.T) {
	data := []byte("Lorem ipsum dolor sit amet")
	tag := byte(0xcc)

	actual := AttachTag(data, tag)
	expected := append([]byte{tag}, data...)

	if !bytes.Equal(actual, expected) {
		t.Errorf("unexpected message: got %q, want %q", actual, expected)
	}
}

func TestDetachTag_DecodesAttachedDadaAndTag(t *testing.T) {
	data := []byte("Lorem ipsum dolor sit amet")
	tag := byte(0xcc)

	msg := AttachTag(data, tag)
	detachedData, detachedTag, err := DetachTag(msg)

	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if !bytes.Equal(detachedData, data) {
		t.Errorf("unexpected data: got %q, want %q", detachedData, data)
	}

	if detachedTag != tag {
		t.Errorf("unexpected tag: got 0x%02x, want 0x%02x", detachedTag, tag)
	}
}

func TestDetachTag_RejectsEmptyMessage(t *testing.T) {
	_, _, err := DetachTag(nil)

	if err == nil {
		t.Errorf("unexpected success")
	} else if err != ErrInvalidMessage {
		t.Errorf("unexpected error: %s", err)
	}
}

func TestDetachTag_InspectsCiphertextMessageTag(t *testing.T) {
	key := []byte("0123456789abcdefghijklmnopqrstuv")
	iv := []byte("0123456789ab")

	sealer, err := NewCipher(key, iv)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	data := []byte("Lorem ipsum dolor sit amet")
	tag := byte(0xcc)

	msg := sealer.Seal(data, tag)
	_, detachedTag, _ := DetachTag(msg)

	if detachedTag != tag {
		t.Errorf("unexpected tag: got 0x%02x, want 0x%02x", detachedTag, tag)
	}
}
