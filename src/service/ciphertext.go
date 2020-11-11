package service

import (
	"encoding/binary"
)

func UnpackCiphertextBlob(data []byte) (ident string, version uint32, ciphertext []byte, ok bool) {

	if len(data) < 1 {
		return // data too short.
	}

	identlength := uint8(data[0])

	//---

	// The length must then be: ident length (1) + ident (A) + version (4) + at least 1 more byte.
	if len(data) < int(1+identlength+4+1) {
		return // data too short.
	}

	// Get the ident
	ident = string(data[1 : identlength+1])

	//---

	// The next 4 bytes are the key version
	v := data[identlength+1 : identlength+5]
	version = binary.LittleEndian.Uint32(v)

	//---

	// The rest of the bytes is the cipher text
	ciphertext = data[identlength+5:]

	ok = true
	return
}
