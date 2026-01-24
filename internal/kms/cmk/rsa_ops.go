package cmk

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"hash"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/nsmithuk/local-kms/internal/kms/validation"
)

//---------------------------------------------
// Operation functions

func (k *RsaKey) GetPublicKey() ([]byte, error) {
	return x509.MarshalPKIXPublicKey(&k.PrivateKey.PublicKey)
}

//---------------------------------------------
// Sign/Verify

func (k *RsaKey) prepSigningDigest(message []byte, algorithm types.SigningAlgorithmSpec, messageType types.MessageType) ([]byte, crypto.Hash, error) {

	digest := message

	if messageType == types.MessageTypeRaw {
		var err error
		digest, err = hashMessage(message, algorithm)
		if err != nil {
			return nil, 0, err
		}
	}

	//---

	var err error
	var hash crypto.Hash

	switch algorithm {
	case types.SigningAlgorithmSpecRsassaPkcs1V15Sha256, types.SigningAlgorithmSpecRsassaPssSha256:
		if len(digest) != (256 / 8) {
			err = fmt.Errorf("invalid signature digest length %d for algorithm %s", len(digest), algorithm)
		}
		hash = crypto.SHA256
	case types.SigningAlgorithmSpecRsassaPkcs1V15Sha384, types.SigningAlgorithmSpecRsassaPssSha384:
		if len(digest) != (384 / 8) {
			err = fmt.Errorf("invalid signature digest length %d for algorithm %s", len(digest), algorithm)
		}
		hash = crypto.SHA384
	case types.SigningAlgorithmSpecRsassaPkcs1V15Sha512, types.SigningAlgorithmSpecRsassaPssSha512:
		if len(digest) != (512 / 8) {
			err = fmt.Errorf("invalid signature digest length %d for algorithm %s", len(digest), algorithm)
		}
		hash = crypto.SHA512
	default:
		err = fmt.Errorf("unsupported signing algorithm %v", algorithm)
	}

	if err != nil {
		return nil, 0, err
	}

	return digest, hash, nil
}

func (k *RsaKey) Sign(message []byte, algorithm types.SigningAlgorithmSpec, messageType types.MessageType) ([]byte, error) {
	if k.GetMetadata().KeyUsage != types.KeyUsageTypeSignVerify {
		return nil, fmt.Errorf("unsupported key usage: %v", k.GetMetadata().KeyUsage)
	}

	digest, hash, err := k.prepSigningDigest(message, algorithm, messageType)
	if err != nil {
		return nil, err
	}

	//---

	key := rsa.PrivateKey(k.PrivateKey)

	//---

	if strings.Contains(string(algorithm), "RSASSA_PKCS1_V1_5_SHA_") {
		return rsa.SignPKCS1v15(rand.Reader, &key, hash, digest)
	}

	// Else we can assume it is PSS.
	return rsa.SignPSS(rand.Reader, &key, hash, digest, nil)
}

func (k *RsaKey) Verify(message []byte, algorithm types.SigningAlgorithmSpec, messageType types.MessageType, signature []byte) (bool, error) {
	if k.GetMetadata().KeyUsage != types.KeyUsageTypeSignVerify {
		return false, fmt.Errorf("unsupported key usage: %v", k.GetMetadata().KeyUsage)
	}

	digest, hash, err := k.prepSigningDigest(message, algorithm, messageType)
	if err != nil {
		return false, err
	}

	//---

	key := rsa.PrivateKey(k.PrivateKey).PublicKey

	//---

	if strings.Contains(string(algorithm), "RSASSA_PKCS1_V1_5_SHA_") {
		err = rsa.VerifyPKCS1v15(&key, hash, digest, signature)
	} else {
		err = rsa.VerifyPSS(&key, hash, digest, signature, nil)
	}

	return err == nil, nil
}

//---------------------------------------------
// Encrypt/Decrypt

func (k *RsaKey) Encrypt(plaintext []byte, algorithm types.EncryptionAlgorithmSpec, context map[string]string) ([]byte, error) {
	if err := k.enforceKeyUsageType(types.KeyUsageTypeEncryptDecrypt); err != nil {
		return nil, err
	}

	if context != nil {
		return nil, fmt.Errorf("encryption context not supported for key type %s", k.GetMetadata().KeySpec)
	}

	//---

	var maxPlaintextLength int

	switch k.GetMetadata().KeySpec {
	case types.KeySpecRsa2048:
		maxPlaintextLength = 190
		if algorithm == types.EncryptionAlgorithmSpecRsaesOaepSha1 {
			maxPlaintextLength = 214
		}
	case types.KeySpecRsa3072:
		maxPlaintextLength = 318
		if algorithm == types.EncryptionAlgorithmSpecRsaesOaepSha1 {
			maxPlaintextLength = 342
		}
	case types.KeySpecRsa4096:
		maxPlaintextLength = 446
		if algorithm == types.EncryptionAlgorithmSpecRsaesOaepSha1 {
			maxPlaintextLength = 470
		}
	default:
		return nil, fmt.Errorf("unknown encryption algorithm %v", k.GetMetadata().KeySpec)
	}

	validator := validation.Validator{}
	err := validator.ByteLength(plaintext, "Plaintext", maxPlaintextLength)
	if err != nil {
		return nil, err
	}

	//---

	var hashAlgorithm hash.Hash
	switch algorithm {
	case types.EncryptionAlgorithmSpecRsaesOaepSha1:
		hashAlgorithm = sha1.New()
	case types.EncryptionAlgorithmSpecRsaesOaepSha256:
		hashAlgorithm = sha256.New()
	default:
		return []byte{}, fmt.Errorf("unknown encryption algorithm %s", algorithm)
	}

	return rsa.EncryptOAEP(hashAlgorithm, rand.Reader, &k.PrivateKey.PublicKey, plaintext, []byte{})
}

func (k *RsaKey) Decrypt(ciphertextblob []byte, algorithm types.EncryptionAlgorithmSpec, context map[string]string) ([]byte, error) {
	if err := k.enforceKeyUsageType(types.KeyUsageTypeEncryptDecrypt); err != nil {
		return nil, err
	}

	if context != nil {
		return nil, fmt.Errorf("encryption context not supported for key type %s", k.GetMetadata().KeySpec)
	}

	//---

	var hashAlgorithm hash.Hash
	switch algorithm {
	case types.EncryptionAlgorithmSpecRsaesOaepSha1:
		hashAlgorithm = sha1.New()
	case types.EncryptionAlgorithmSpecRsaesOaepSha256:
		hashAlgorithm = sha256.New()
	default:
		return []byte{}, fmt.Errorf("unknown encryption algorithm %s", algorithm)
	}

	key := rsa.PrivateKey(k.PrivateKey)
	return rsa.DecryptOAEP(hashAlgorithm, rand.Reader, &key, ciphertextblob, []byte{})
}
