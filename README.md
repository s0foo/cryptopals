# Cryptopals

Go solutions to the [Cryptopals Crypto Challenges](https://cryptopals.com/).

## Progress

### Set 1 — Basics

- [x] 1. Convert hex to base64
- [x] 2. Fixed XOR
- [x] 3. Single-byte XOR cipher
- [x] 4. Detect single-character XOR
- [x] 5. Implement repeating-key XOR
- [x] 6. Break repeating-key XOR
- [x] 7. AES in ECB mode
- [x] 8. Detect AES in ECB mode

### Set 2 — Block crypto

- [x] 9. Implement PKCS#7 padding
- [x] 10. Implement CBC mode
- [x] 11. An ECB/CBC detection oracle
- [x] 12. Byte-at-a-time ECB decryption (Simple)
- [x] 13. ECB cut-and-paste
- [ ] 14+

## Structure

```
set1.go / set1_test.go   Challenges 1-8
set2.go / set2_test.go   Challenges 9-13
data/                    Challenge inputs (and alice.txt, used as a
                          letter-frequency corpus for XOR scoring)
```

## Requirements

Go 1.25+ (see `go.mod`).

## Running tests

```sh
go test ./... -v
```

Most challenge tests log the recovered plaintext/key with `t.Logf` rather
than asserting on it — check the `-v` output to see the results.
