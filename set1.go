package cryptopals

import (
	"encoding/base64"
	"encoding/hex"
	"math"
	"math/bits"
	"unicode/utf8"
)

func hex2Base64(hexString string) (string, error) {
	res, err := hex.DecodeString(hexString)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(res), nil
}

func xor(a, b []byte) []byte {
	l := len(a)
	if l != len(b) {
		panic("[xor] Buffers must have the same length.")
	}
	c := make([]byte, l)
	for i := 0; i < l; i++ {
		c[i] = a[i] ^ b[i]
	}
	return c
}

func letterFrequency(text string) map[rune]float64 {
	freq := make(map[rune]float64)
	total := 0.0

	for _, char := range text {
		freq[char]++
		total++
	}

	for char := range freq {
		freq[char] = (freq[char] / total)
	}

	return freq
}

func buildCorpus(text string) map[rune]float64 {
	c := make(map[rune]float64)
	for _, char := range text {
		c[char]++
	}
	total := utf8.RuneCountInString(text)
	for char := range c {
		c[char] = c[char] / float64(total)
	}
	return c
}

func scoreText(text string, corpus map[rune]float64) float64 {
	observedFreq := letterFrequency(text)
	score := 0.0

	for char, expected := range corpus {
		observed, exists := observedFreq[char]
		if !exists {
			observed = 0.0
		}
		score += (1 - (observed-expected)*(observed-expected))
	}

	return score
}

func singleXor(src []byte, key byte) []byte {
	output := make([]byte, len(src))
	for i, b := range src {
		output[i] = b ^ key
	}
	return output
}

func singleCharacterXorFinder(masked []byte, corpus map[rune]float64) ([]byte, byte) {
	var key byte
	var maxScore float64
	var res []byte
	var score float64
	var unmasked []byte

	for k := 0; k < 256; k++ {
		unmasked = singleXor(masked, byte(k))
		score = scoreText(string(unmasked), corpus)
		if score > maxScore {
			maxScore = score
			key = byte(k)
			res = unmasked
		}
	}

	return res, key
}

func repeatingKeyXor(in, key []byte) []byte {
	out := make([]byte, len(in))
	for i := 0; i < len(in); i++ {
		out[i] = in[i] ^ key[i%len(key)]
	}
	return out
}

func hammingDistance(a, b []byte) int {
	d := 0
	if len(a) != len(b) {
		panic("[hammingDistance] Buffers must have the same length.")
	}
	for i := 0; i < len(a); i++ {
		d += bits.OnesCount8(a[i] ^ b[i])
	}
	return d
}

func findKeySize(in []byte) int {
	var distance float64
	var keysize int
	minimalDistance := math.MaxFloat64

	for ks := 2; ks < 40; ks++ {
		distance = float64(hammingDistance(in[:ks*4], in[ks*4:ks*8])) / float64(ks)
		if distance < minimalDistance {
			minimalDistance = distance
			keysize = ks
		}
	}

	return keysize
}

func findXorKey(in []byte, corpus map[rune]float64) []byte {
	keysize := findKeySize(in)
	c := make([]byte, (len(in)+keysize-1)/keysize)
	key := make([]byte, keysize)

	for i := 0; i < keysize; i++ {
		for j := 0; j < len(c); j++ {
			if j*keysize+i >= len(in) {
				continue
			}
			c[j] = in[j*keysize+i]
		}
		_, k := singleCharacterXorFinder(c, corpus)
		key[i] = k
	}

	return key
}
