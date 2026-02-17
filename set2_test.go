package cryptopals

import (
	"bytes"
	"testing"
)

func TestChallenge9(t *testing.T) {
	res := pkcs7Padding([]byte("YELLOW SUBMARINE"), 20)
	expected := []byte("YELLOW SUBMARINE\x04\x04\x04\x04")
	if !bytes.Equal(res, expected) {
		t.Error("Wrong output:", res)
	}

	// Test also edge case
	res = pkcs7Padding([]byte("YELLOW SUBMARINE"), 16)
	expected = []byte("YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10")
	if !bytes.Equal(res, expected) {
		t.Error("Wrong output:", res)
	}
}
