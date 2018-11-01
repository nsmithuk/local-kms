package service

import (
	"crypto/aes"
	"crypto/cipher"
)

func Encrypt(key [32]byte, plaintext []byte) (result []byte, err error) {

	block, err := aes.NewCipher([]byte(key[:]))
	if err != nil {
		return
	}

	nonce := GenerateRandomData(12)

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

	result = append(nonce, ciphertext...)

	return
}

func Decrypt(key [32]byte, ciphertext []byte) (plaintext []byte, err error) {

	nonce := ciphertext[:12]

	block, err := aes.NewCipher([]byte(key[:]))
	if err != nil {
		return
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}

	plaintext, err = aesgcm.Open(nil, nonce, ciphertext[12:], nil)
	if err != nil {
		return
	}

	return
}