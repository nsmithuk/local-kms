package cmk

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

//---------------------------------------------
// Operation functions

func (k *Ed25519Key) GetPublicKey() ([]byte, error) {
	return x509.MarshalPKIXPublicKey(k.PublicKey)
}

func (k *Ed25519Key) Sign(message []byte, algorithm types.SigningAlgorithmSpec, messageType types.MessageType) ([]byte, error) {
	if err := k.enforceKeyUsageType(types.KeyUsageTypeSignVerify); err != nil {
		return nil, err
	}

	// When using ECC_NIST_EDWARDS25519 KMS keys:
	//   - ED25519_SHA_512 signing algorithm requires KMS MessageType:RAW
	//   - ED25519_PH_SHA_512 signing algorithm requires KMS MessageType:DIGEST

	if algorithm == types.SigningAlgorithmSpecEd25519Sha512 && messageType != types.MessageTypeRaw {
		return nil, fmt.Errorf("algorithm is %s, message type must be %s", types.SigningAlgorithmSpecEd25519Sha512, types.MessageTypeRaw)
	}

	if algorithm == types.SigningAlgorithmSpecEd25519PhSha512 && messageType != types.MessageTypeDigest {
		return nil, fmt.Errorf("algorithm is %s, message type must be %s", types.SigningAlgorithmSpecEd25519PhSha512, types.MessageTypeDigest)
	}

	if algorithm == types.SigningAlgorithmSpecEd25519PhSha512 {
		if len(message) != (512 / 8) {
			return nil, fmt.Errorf("invalid signature digest length %d for algorithm %s", len(message), algorithm)
		}

		return k.PrivateKey.Sign(rand.Reader, message, crypto.SHA512)
	}

	return ed25519.Sign(k.PrivateKey, message), nil
}

func (k *Ed25519Key) Verify(message []byte, algorithm types.SigningAlgorithmSpec, messageType types.MessageType, signature []byte) (bool, error) {
	if err := k.enforceKeyUsageType(types.KeyUsageTypeSignVerify); err != nil {
		return false, err
	}

	// When using ECC_NIST_EDWARDS25519 KMS keys:
	//   - ED25519_SHA_512 signing algorithm requires KMS MessageType:RAW
	//   - ED25519_PH_SHA_512 signing algorithm requires KMS MessageType:DIGEST

	if algorithm == types.SigningAlgorithmSpecEd25519Sha512 && messageType != types.MessageTypeRaw {
		return false, fmt.Errorf("algorithm is %s, message type must be %s", types.SigningAlgorithmSpecEd25519Sha512, types.MessageTypeRaw)
	}

	if algorithm == types.SigningAlgorithmSpecEd25519PhSha512 && messageType != types.MessageTypeDigest {
		return false, fmt.Errorf("algorithm is %s, message type must be %s", types.SigningAlgorithmSpecEd25519PhSha512, types.MessageTypeDigest)
	}

	if algorithm == types.SigningAlgorithmSpecEd25519PhSha512 {
		if len(message) != (512 / 8) {
			return false, fmt.Errorf("invalid signature digest length %d for algorithm %s", len(message), algorithm)
		}

		err := ed25519.VerifyWithOptions(k.PublicKey, message, signature, &ed25519.Options{Hash: crypto.SHA512})
		return err == nil, nil
	}

	// Standard Ed25519 verify of the RAW message
	return ed25519.Verify(k.PublicKey, message, signature), nil
}
