package main

import (
	"crypto/aes"
	"crypto/rand"
	"io"
	"crypto/cipher"
	"encoding/base64"
	"log"
)

func encrypt( key []byte, plaintextString string ) []byte {

	plaintext := []byte(plaintextString)

	block, err := aes.NewCipher(key)
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


func decrypt( key []byte, ciphertext []byte ) string {

	nonce := ciphertext[:12]

	log.Println(nonce)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext[12:], nil)
	if err != nil {
		panic(err.Error())
	}

	return string(plaintext)
}


func encode( data []byte ) string {
	return base64.StdEncoding.EncodeToString(data)
}

func decode( data string ) ([]byte, error) {
	return base64.StdEncoding.DecodeString(data)
}
