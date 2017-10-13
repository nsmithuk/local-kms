package main

import (
	"crypto/sha256"
)

/*
Crude fake key generation; a sha256 of the ident.
 */
func getKey( ident string ) []byte {

	fakeKey := sha256.Sum256([]byte(ident))

	return []byte(fakeKey[:])
}

func appendKeyIdent( ident string, data []byte ) []byte {

	identBytes := []byte(ident)

	identlength := len(identBytes)

	/*
		Final result will be the length of:
			- the passed data
			- The key ident
			- One bytes holding the length of the key ident
	 */
	result := make([]byte, 1 + identlength + len(data))

	result[0] = byte(identlength)

	copy(result[1:], identBytes)

	copy(result[identlength+1:], data)

	return result
}

func extractKeyIdent( data []byte ) (string, []byte) {

	identlength := uint8(data[0])

	// We need the plus one to step over the fist 'length' byte.
	return string(data[1:identlength+1]), data[identlength+1:]
}