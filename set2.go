package cryptopals

import "bytes"

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
