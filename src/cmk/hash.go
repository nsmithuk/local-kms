package cmk

import (
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
)

func hashMessage(message []byte, algorithm SigningAlgorithm) ([]byte, error) {

	//--------------------------
	// Hash the message

	var digest hash.Hash

	switch algorithm {
	case SigningAlgorithmEcdsaSha256, SigningAlgorithmRsaPssSha256, SigningAlgorithmRsaPkcsSha256:
		digest = sha256.New()
	case SigningAlgorithmEcdsaSha384, SigningAlgorithmRsaPssSha384, SigningAlgorithmRsaPkcsSha384:
		digest = sha512.New384()
	case SigningAlgorithmEcdsaSha512, SigningAlgorithmRsaPssSha512, SigningAlgorithmRsaPkcsSha512:
		digest = sha512.New()
	default:
		return []byte{}, errors.New("unknown signing algorithm")
	}

	digest.Write(message)
	return digest.Sum(nil), nil
}
