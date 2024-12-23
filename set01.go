package cryptopals

import (
	"encoding/base64"
	"encoding/hex"
	"log"
)

func HexToBase64(hs string) (string, error) {
	bs, err := hex.DecodeString(hs)
	if err != nil {
		return "", err
	}
	log.Printf("%s", bs)
	return base64.StdEncoding.EncodeToString(bs), err
}
