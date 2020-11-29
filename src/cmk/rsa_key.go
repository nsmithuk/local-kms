package cmk

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
)

type RsaPrivateKey rsa.PrivateKey

type RsaKey struct {
	BaseKey
	PrivateKey RsaPrivateKey
}

func NewRsaKey(spec CustomerMasterKeySpec, usage KeyUsage, metadata KeyMetadata, policy string) (*RsaKey, error) {

	var bits int

	switch spec {
	case SpecRsa2048:
		bits = 2048
	case SpecRsa3072:
		bits = 3072
	case SpecRsa4096:
		bits = 4096
	default:
		return nil, errors.New("key spec error")
	}

	//---

	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}

	k := &RsaKey{
		PrivateKey: RsaPrivateKey(*privateKey),
	}

	k.Type = TypeRsa
	k.Metadata = metadata
	k.Policy = policy

	k.Metadata.KeyUsage = usage
	k.Metadata.CustomerMasterKeySpec = spec

	switch usage {
	case UsageSignVerify:

		k.Metadata.SigningAlgorithms = []SigningAlgorithm{
			SigningAlgorithmRsaPssSha256,
			SigningAlgorithmRsaPssSha384,
			SigningAlgorithmRsaPssSha512,
			SigningAlgorithmRsaPkcsSha256,
			SigningAlgorithmRsaPkcsSha384,
			SigningAlgorithmRsaPkcsSha512,
		}

	case UsageEncryptDecrypt:

		k.Metadata.EncryptionAlgorithms = []EncryptionAlgorithm{
			EncryptionAlgorithmRsaOaepSha1,
			EncryptionAlgorithmRsaOaepSha256,
		}

	default:
		return nil, errors.New("key usage error")
	}

	return k, nil
}

//----------------------------------------------------

func (k *RsaKey) GetArn() string {
	return k.GetMetadata().Arn
}

func (k *RsaKey) GetPolicy() string {
	return k.Policy
}

func (k *RsaKey) GetKeyType() KeyType {
	return k.Type
}

func (k *RsaKey) GetMetadata() *KeyMetadata {
	return &k.Metadata
}

//----------------------------------------------------

func (k *RsaKey) Sign(digest []byte, algorithm SigningAlgorithm) ([]byte, error) {

	//--------------------------
	// Check the requested Signing Algorithm is supported by this key

	validSigningAlgorithm := false

	for _, a := range k.Metadata.SigningAlgorithms {
		if a == algorithm {
			validSigningAlgorithm = true
			break
		}
	}

	if !validSigningAlgorithm {
		return []byte{}, &InvalidSigningAlgorithm{}
	}

	//--------------------------

	var hash crypto.Hash

	switch algorithm {
	case SigningAlgorithmRsaPssSha256, SigningAlgorithmRsaPkcsSha256:
		if len(digest) != (256 / 8) {
			return []byte{}, &InvalidDigestLength{}
		}
		hash = crypto.SHA256
	case SigningAlgorithmRsaPssSha384, SigningAlgorithmRsaPkcsSha384:
		if len(digest) != (384 / 8) {
			return []byte{}, &InvalidDigestLength{}
		}
		hash = crypto.SHA384
	case SigningAlgorithmRsaPssSha512, SigningAlgorithmRsaPkcsSha512:
		if len(digest) != (512 / 8) {
			return []byte{}, &InvalidDigestLength{}
		}
		hash = crypto.SHA512
	default:
		return []byte{}, errors.New("unknown signing algorithm")
	}

	//---

	key := rsa.PrivateKey(k.PrivateKey)

	switch algorithm {
	case SigningAlgorithmRsaPssSha256, SigningAlgorithmRsaPssSha384, SigningAlgorithmRsaPssSha512:

		return rsa.SignPSS(rand.Reader, &key, hash, digest, nil)

	case SigningAlgorithmRsaPkcsSha256, SigningAlgorithmRsaPkcsSha384, SigningAlgorithmRsaPkcsSha512:

		return rsa.SignPKCS1v15(rand.Reader, &key, hash, digest)

	default:
		return []byte{}, errors.New("unknown signing algorithm")
	}
}

func (k *RsaKey) HashAndSign(message []byte, algorithm SigningAlgorithm) ([]byte, error) {

	digest, err := hashMessage(message, algorithm)
	if err != nil {
		return []byte{}, err
	}

	return k.Sign(digest, algorithm)
}

//----------------------------------------------------

func (k *RsaKey) Verify(signature []byte, digest []byte, algorithm SigningAlgorithm) (bool, error) {

	var hash crypto.Hash

	switch algorithm {
	case SigningAlgorithmRsaPssSha256, SigningAlgorithmRsaPkcsSha256:
		hash = crypto.SHA256
	case SigningAlgorithmRsaPssSha384, SigningAlgorithmRsaPkcsSha384:
		hash = crypto.SHA384
	case SigningAlgorithmRsaPssSha512, SigningAlgorithmRsaPkcsSha512:
		hash = crypto.SHA512
	default:
		return false, errors.New("unknown signing algorithm")
	}

	//---

	key := rsa.PrivateKey(k.PrivateKey)

	switch algorithm {
	case SigningAlgorithmRsaPssSha256, SigningAlgorithmRsaPssSha384, SigningAlgorithmRsaPssSha512:

		if err := rsa.VerifyPSS(&key.PublicKey, hash, digest, signature, nil); err != nil {
			return false, nil
		}

	case SigningAlgorithmRsaPkcsSha256, SigningAlgorithmRsaPkcsSha384, SigningAlgorithmRsaPkcsSha512:

		if err := rsa.VerifyPKCS1v15(&key.PublicKey, hash, digest, signature); err != nil {
			return false, nil
		}

	default:
		return false, errors.New("unknown signing algorithm")
	}

	return true, nil
}

func (k *RsaKey) HashAndVerify(signature []byte, message []byte, algorithm SigningAlgorithm) (bool, error) {

	digest, err := hashMessage(message, algorithm)
	if err != nil {
		return false, err
	}

	return k.Verify(signature, digest, algorithm)
}
