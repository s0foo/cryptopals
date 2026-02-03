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
