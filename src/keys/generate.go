package keys

import (
	"crypto/sha256"
)

/*
Crude fake key generation; a sha256 of the ident.
 */
func GetKey( ident string ) [32]byte {

	return sha256.Sum256([]byte(ident))
}
