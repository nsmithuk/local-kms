package cmk

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"hash"
)

func (k *RsaKey) Encrypt(plaintext []byte, algorithm EncryptionAlgorithm) (result []byte, err error) {
	var hashAlgorithm hash.Hash
	switch algorithm {
	case EncryptionAlgorithmRsaOaepSha1:
		hashAlgorithm = sha1.New()
	case EncryptionAlgorithmRsaOaepSha256:
		hashAlgorithm = sha256.New()
	default:
		return []byte{}, errors.New("unknown encryption algorithm")
	}

	return rsa.EncryptOAEP(hashAlgorithm, rand.Reader, &k.PrivateKey.PublicKey, plaintext, []byte{})
}

func (k *RsaKey) Decrypt(ciphertext []byte, algorithm EncryptionAlgorithm) (plaintext []byte, err error) {
	var hashAlgorithm hash.Hash
	switch algorithm {
	case EncryptionAlgorithmRsaOaepSha1:
		hashAlgorithm = sha1.New()
	case EncryptionAlgorithmRsaOaepSha256:
		hashAlgorithm = sha256.New()
	default:
		return []byte{}, errors.New("unknown encryption algorithm")
	}

	key := rsa.PrivateKey(k.PrivateKey)
	return rsa.DecryptOAEP(hashAlgorithm, rand.Reader, &key, ciphertext, []byte{})
}
