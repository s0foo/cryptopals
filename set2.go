package cryptopals

import "bytes"

func pkcs7Padding(in []byte, blockSize int) []byte {
	if blockSize > 255 {
		panic("[pkcs7Padding] blockSize too large")
	}
	padLength := blockSize - len(in)%blockSize
	return append(in, bytes.Repeat([]byte{byte(padLength)}, padLength)...)
}
