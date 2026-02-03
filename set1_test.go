package cryptopals

import (
        "encoding/hex"
        "testing"
)

func TestChallenge1(t *testing.T) {
        res, err := hex2Base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
        if err != nil {
                t.Fatal(err)
        }
        if res != "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" {
                t.Error("Wrong output:", res)
        }
}

func TestChallenge2(t *testing.T) {
        b1, _ := hex.DecodeString("1c0111001f010100061a024b53535009181c")
        b2, _ := hex.DecodeString("686974207468652062756c6c277320657965")
        res := hex.EncodeToString(xor(b1, b2))
        if res != "746865206b696420646f6e277420706c6179" {
                t.Error("Wrong output:", res)
        }
}
