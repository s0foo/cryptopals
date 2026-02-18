package cryptopals

import (
	"bytes"
	"encoding/base64"
	"os"
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

func TestChallenge10(t *testing.T) {
	data, err := os.ReadFile("data/10.txt")
	if err != nil {
		t.Logf("Error reading file: %v\n", err)
		return
	}
	rawData, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		t.Log("Error decoding file")
		return
	}
	key := []byte("YELLOW SUBMARINE")
	iv := bytes.Repeat([]byte("\x00"), len(key))
	plain := decryptCBC(iv, rawData, key)
	t.Logf("Plaintext: %s", string(plain))
}
