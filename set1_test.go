package cryptopals

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"os"
	"strings"
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

func corpusFromFile(name string) map[rune]float64 {
	text, err := os.ReadFile(name)
	if err != nil {
		panic("failed to read text file")
	}
	return buildCorpus(string(text))
}

var corpus = corpusFromFile("data/alice.txt")

func TestChallenge3(t *testing.T) {
	m, _ := hex.DecodeString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	res, key := singleCharacterXorFinder(m, corpus)
	t.Logf("Key: %c", key)
	t.Logf("Message: %s", string(res))
}

func TestChallenge4(t *testing.T) {
	file, err := os.Open("data/4.txt")
	if err != nil {
		t.Error(err)
	}
	defer file.Close()

	score := 0.0
	maxScore := 0.0

	var masked []byte
	var unmasked []byte
	var res []byte

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		masked, _ = hex.DecodeString(scanner.Text())
		res, _ = singleCharacterXorFinder(masked, corpus)
		score = scoreText(string(res), corpus)
		if score > maxScore {
			maxScore = score
			unmasked = res
		}
	}
	t.Logf("Message: %s", string(unmasked))
}

func TestChallenge5(t *testing.T) {
	in := []byte(`Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`)
	key := []byte("ICE")
	res := repeatingKeyXor(in, key)
	ref, _ := hex.DecodeString("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
	if !bytes.Equal(res, ref) {
		t.Error("Wrong output:", res)
	}
}

func TestChallenge6(t *testing.T) {
	// Hamming distance test
	a := []byte("this is a test")
	b := []byte("wokka wokka!!!")
	d := hammingDistance(a, b)
	if d != 37 {
		t.Error("Wrong Hamming distance:", d)
	}

	// Challenge 6
	data, err := os.ReadFile("data/6.txt")
	if err != nil {
		t.Logf("Error reading file: %v\n", err)
		return
	}
	rawData, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		t.Log("Error decoding file")
		return
	}

	key := findXorKey(rawData, corpus)
	t.Logf("Key: %s", string(key))
	t.Log(string(repeatingKeyXor(rawData, key)))
}

func TestChallenge7(t *testing.T) {
	data, err := os.ReadFile("data/7.txt")
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
	plain := decryptECB(rawData, key)
	t.Logf("Plaintext: %s", string(plain))
}

func TestChallenge8(t *testing.T) {
	data, err := os.ReadFile("data/8.txt")
	if err != nil {
		t.Logf("Error reading file: %v\n", err)
		return
	}
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if detectECB([]byte(line), 16) {
			t.Logf("ECB detect at line: %d", i+1)
		}
	}
}
