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
