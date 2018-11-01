package service

import (
	"encoding/binary"
)

func ConstructCipherResponse(ident string, version uint32, data []byte) []byte {

	identBytes := []byte(ident)

	v := make([]byte, 4)
	binary.LittleEndian.PutUint32(v, version)

	/*
		Final result will be:
			- The length of the ident
			- The ident
			- The version (uint32 = 4 bytes)
			- The data
	 */

	result := []byte{byte(len(identBytes))}
	result = append( result, identBytes... )
	result = append( result, v... )
	result = append( result, data... )

	return result
}

func DeconstructCipherResponse(data []byte) (ident string, version uint32, ciphertext []byte) {

	identlength := uint8(data[0])

	// Get the ident
	ident = string(data[1:identlength+1])

	// The next 4 bytes are the key version
	v := data[identlength+1:identlength+5]
	version = binary.LittleEndian.Uint32(v)

	// The rest of the bytes is the cipher text
	ciphertext = data[identlength+5:]

	return
}
