package cryptopals

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func HexDecode(t *testing.T, s string) []byte {
        bs, err := hex.DecodeString(s)
        if err != nil {
                t.Fatal("failed to decode hexadecimal string:", s)
        }
        return bs
}

func TestChallenge01(t *testing.T) {
	in := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	expected := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	got, err := HexToBase64(in)
	if err != nil {
		t.Errorf("HexToBase64 internal error")
	}
	if got != expected {
		t.Errorf("expected %s but got %s", expected, got)
	}
}

func TestChallenge02(t *testing.T) {
        expected := HexDecode(t, "746865206b696420646f6e277420706c6179")
        got := Xor(HexDecode(t, "1c0111001f010100061a024b53535009181c"), HexDecode(t, "686974207468652062756c6c277320657965"))
        if !bytes.Equal(got, expected) {
                t.Errorf("expected %x but got %x", expected, got)
        }
}
