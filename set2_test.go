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

func TestChallenge11(t *testing.T) {
	plaintext := bytes.Repeat([]byte("A"), 48)
	for i := 0; i < 100; i++ {
		ciphertext, actual := encryptionOracle(plaintext)
		detected := detectMode(ciphertext)
		if detected != actual {
			t.Errorf("Detection mismatch: got %s, want %s", detected, actual)
		}
	}
}

func TestEncryptDecryptCBCRoundTrip(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	iv := bytes.Repeat([]byte{0}, len(key))
	plaintext := []byte("Some plaintext that is definitely not a multiple of the block size!")

	ciphertext := encryptCBC(iv, append([]byte{}, plaintext...), key)
	decrypted := decryptCBC(iv, ciphertext, key)

	expected := pkcs7Padding(append([]byte{}, plaintext...), len(key))
	if !bytes.Equal(decrypted, expected) {
		t.Errorf("CBC round trip mismatch: got %q, want %q", decrypted, expected)
	}
}

func TestChallenge12(t *testing.T) {
	expected := "Rollin' in my 5.0\n" +
		"With my rag-top down so my hair can blow\n" +
		"The girlies on standby waving just to say hi\n" +
		"Did you stop? No, I just drove by\n"

	blockSize := discoverBlockSize(ecbOracle12)
	if blockSize != 16 {
		t.Fatalf("Wrong block size: %d", blockSize)
	}

	if !detectECB(ecbOracle12(bytes.Repeat([]byte{'A'}, blockSize*2)), blockSize) {
		t.Fatal("Oracle does not appear to use ECB")
	}

	plain := decryptECBByteAtATime(ecbOracle12, blockSize)
	t.Logf("Plaintext:\n%s", string(plain))

	if string(plain) != expected {
		t.Error("Recovered plaintext does not match the expected string")
	}
}
