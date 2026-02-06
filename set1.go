package cryptopals

import (
	"encoding/base64"
	"encoding/hex"
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

func englishLetterFrequencies() map[rune]float64 {
	return map[rune]float64{
		'a': 0.06517, 'b': 0.01242, 'c': 0.02173, 'd': 0.03492,
		'e': 0.10414, 'f': 0.01978, 'g': 0.01586, 'h': 0.04928,
		'i': 0.05580, 'j': 0.00090, 'k': 0.00507, 'l': 0.03314,
		'm': 0.02021, 'n': 0.05645, 'o': 0.05963, 'p': 0.01376,
		'q': 0.00086, 'r': 0.04971, 's': 0.05157, 't': 0.07293,
		'u': 0.02251, 'v': 0.00829, 'w': 0.01712, 'x': 0.00136,
		'y': 0.01459, 'z': 0.00074, ' ': 0.18288,
	}
}

func scoreText(text string) float64 {
	observedFreq := letterFrequency(text)
	expectedFreq := englishLetterFrequencies()

	score := 0.0

	for char, expected := range expectedFreq {
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

func singleCharacterXorFinder(masked []byte) ([]byte, byte) {
	var key byte
	var maxScore float64
	var res []byte
	var score float64
	var unmasked []byte

	for k := 0; k < 256; k++ {
		unmasked = singleXor(masked, byte(k))
		score = scoreText(string(unmasked))
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
