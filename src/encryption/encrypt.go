package encryption

import (
	"crypto/aes"
	"crypto/rand"
	"io"
	"crypto/cipher"
	"log"
)

func Encrypt( key [32]byte, plaintextString string ) []byte {

	plaintext := []byte(plaintextString)

	block, err := aes.NewCipher([]byte(key[:]))
	if err != nil {
		panic(err.Error())
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	log.Println(nonce)

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

	result := make([]byte, len(nonce) + len(ciphertext))

	copy(result, nonce)
	copy(result[12:], ciphertext)

	return result
}

