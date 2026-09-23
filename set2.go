package cryptopals

import (
	"bytes"
	"crypto/aes"
	crand "crypto/rand"
	"encoding/base64"
	"errors"
	mrand "math/rand"
	"strings"
)

func pkcs7Padding(in []byte, blockSize int) []byte {
	if blockSize > 255 {
		panic("[pkcs7Padding] blockSize too large")
	}
	padLength := blockSize - len(in)%blockSize
	return append(in, bytes.Repeat([]byte{byte(padLength)}, padLength)...)
}

func decryptCBC(iv, in, key []byte) []byte {
	ecbDecrypted := decryptECB(in, key)
	var out []byte
	bs := len(iv)

	out = append(out, xor(ecbDecrypted[:bs], iv)...)
	for i := 0; i < len(in)-bs; i += bs {
		out = append(out, xor(ecbDecrypted[i+bs:i+2*bs], in[i:i+bs])...)
	}

	return out
}

func encryptECB(in, key []byte) []byte {
	c, err := aes.NewCipher(key)
	if err != nil {
		panic("[encryptECB] cannot create AES cipher")
	}
	return ecbBlocks(in, len(key), c.Encrypt)
}

func encryptCBC(iv, in, key []byte) []byte {
	bs := len(iv)
	padded := pkcs7Padding(in, bs)

	var out []byte
	prev := iv
	for i := 0; i < len(padded); i += bs {
		enc := encryptECB(xor(padded[i:i+bs], prev), key)
		out = append(out, enc...)
		prev = enc
	}

	return out
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := crand.Read(b); err != nil {
		panic("[randomBytes] cannot generate random bytes")
	}
	return b
}

// encryptionOracle pads in with 5-10 random bytes on each side, then
// encrypts it under a random key using ECB or CBC (chosen at random).
// It returns the ciphertext along with the mode actually used, so
// callers can check a detector's guess against the truth.
func encryptionOracle(in []byte) (ciphertext []byte, mode string) {
	key := randomBytes(16)
	data := append(randomBytes(5+mrand.Intn(6)), in...)
	data = append(data, randomBytes(5+mrand.Intn(6))...)

	if mrand.Intn(2) == 0 {
		return encryptECB(pkcs7Padding(data, 16), key), "ECB"
	}
	return encryptCBC(randomBytes(16), data, key), "CBC"
}

func detectMode(ciphertext []byte) string {
	if detectECB(ciphertext, 16) {
		return "ECB"
	}
	return "CBC"
}

var ecbOracleKey = randomBytes(16)

var unknownString12 = mustBase64Decode(
	"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK",
)

func mustBase64Decode(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic("[mustBase64Decode] invalid base64 input")
	}
	return b
}

func ecbOracle12(in []byte) []byte {
	data := append(append([]byte{}, in...), unknownString12...)
	return encryptECB(pkcs7Padding(data, 16), ecbOracleKey)
}

func discoverBlockSize(oracle func([]byte) []byte) int {
	initialLen := len(oracle(nil))
	for i := 1; i < 256; i++ {
		newLen := len(oracle(bytes.Repeat([]byte{'A'}, i)))
		if newLen != initialLen {
			return newLen - initialLen
		}
	}
	panic("[discoverBlockSize] could not discover block size")
}

// ecbSecretLength recovers the length of the fixed secret appended by the
// oracle: the output length only grows once enough attacker bytes have been
// added to absorb the secret's own PKCS#7 padding, at which point the pad
// length k satisfies secretLen = initialLen - k.
func ecbSecretLength(oracle func([]byte) []byte, blockSize int) int {
	initialLen := len(oracle(nil))
	for k := 1; k <= blockSize; k++ {
		if len(oracle(bytes.Repeat([]byte{'A'}, k))) != initialLen {
			return initialLen - k
		}
	}
	panic("[ecbSecretLength] could not discover secret length")
}

func decryptECBByteAtATime(oracle func([]byte) []byte, blockSize int) []byte {
	probe := bytes.Repeat([]byte{'A'}, blockSize*2)
	if !detectECB(oracle(probe), blockSize) {
		panic("[decryptECBByteAtATime] oracle is not using ECB")
	}

	secretLen := ecbSecretLength(oracle, blockSize)

	var known []byte
	for i := 0; i < secretLen; i++ {
		blockIndex := i / blockSize
		padLen := blockSize - 1 - i%blockSize
		prefix := bytes.Repeat([]byte{'A'}, padLen)
		target := oracle(prefix)[blockIndex*blockSize : (blockIndex+1)*blockSize]

		input := append(append([]byte{}, prefix...), known...)
		input = append(input, 0)

		for b := 0; b < 256; b++ {
			input[len(input)-1] = byte(b)
			candidate := oracle(input)[blockIndex*blockSize : (blockIndex+1)*blockSize]
			if bytes.Equal(candidate, target) {
				known = append(known, byte(b))
				break
			}
		}
	}

	return known
}

// pkcs7Unpad strips PKCS#7 padding, rejecting input whose padding is
// malformed.
func pkcs7Unpad(in []byte, blockSize int) ([]byte, error) {
	if len(in) == 0 || len(in)%blockSize != 0 {
		return nil, errors.New("[pkcs7Unpad] input is not a multiple of the block size")
	}
	padLen := int(in[len(in)-1])
	if padLen == 0 || padLen > blockSize {
		return nil, errors.New("[pkcs7Unpad] invalid padding length")
	}
	if !bytes.Equal(in[len(in)-padLen:], bytes.Repeat([]byte{byte(padLen)}, padLen)) {
		return nil, errors.New("[pkcs7Unpad] invalid padding bytes")
	}
	return in[:len(in)-padLen], nil
}

// parseKV parses a "foo=bar&baz=qux" string into a map.
func parseKV(s string) (map[string]string, error) {
	out := make(map[string]string)
	for _, pair := range strings.Split(s, "&") {
		k, v, ok := strings.Cut(pair, "=")
		if !ok {
			return nil, errors.New("[parseKV] malformed pair: " + pair)
		}
		out[k] = v
	}
	return out, nil
}

// profileFor encodes a user profile for email. Metacharacters are stripped
// so the caller cannot inject their own "&role=admin".
func profileFor(email string) string {
	email = strings.NewReplacer("&", "", "=", "").Replace(email)
	return "email=" + email + "&uid=10&role=user"
}

var profileKey = randomBytes(16)

func encryptProfile(email string) []byte {
	return encryptECB(pkcs7Padding([]byte(profileFor(email)), 16), profileKey)
}

func decryptProfile(ciphertext []byte) (map[string]string, error) {
	plain, err := pkcs7Unpad(decryptECB(ciphertext, profileKey), 16)
	if err != nil {
		return nil, err
	}
	return parseKV(string(plain))
}

// forgeAdminProfile builds a ciphertext that decrypts to a role=admin
// profile using only calls to encryptProfile, by cutting and pasting ECB
// blocks from two different encryptions.
func forgeAdminProfile() []byte {
	const bs = 16
	prefix := "email="
	fill := strings.Repeat("A", bs-len(prefix))

	// Block 1 of this encryption is exactly "admin" + PKCS#7 padding,
	// i.e. what a final "admin" block looks like.
	adminBlock := pkcs7Padding([]byte("admin"), bs)
	adminCipher := encryptProfile(fill + string(adminBlock))[bs : 2*bs]

	// Choose an email length so that "email=...&uid=10&role=" ends on a
	// block boundary, leaving "user" + padding alone in the last block.
	head := len(prefix) + len("&uid=10&role=")
	emailLen := bs - head%bs
	if emailLen < len("@x.io") {
		emailLen += bs
	}
	email := strings.Repeat("a", emailLen-len("@x.io")) + "@x.io"
	userCipher := encryptProfile(email)

	cut := len(userCipher) - bs
	return append(append([]byte{}, userCipher[:cut]...), adminCipher...)
}
