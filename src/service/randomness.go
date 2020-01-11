package service

import (
	"crypto/rand"
	"io"
)

func GenerateRandomData(size uint16) []byte {
	data := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		panic(err)
	}
	return data
}
