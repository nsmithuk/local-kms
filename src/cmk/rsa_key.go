package cmk

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

type RsaPrivateKey rsa.PrivateKey

type RsaKey struct {
	BaseKey
	PrivateKey RsaPrivateKey
}

func NewRsaKey(spec KeySpec, usage KeyUsage, metadata KeyMetadata, policy string) (*RsaKey, error) {

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
	k.Metadata.KeySpec = spec
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

//----------------------------------------------------
// Construct key from YAML (seeding)
//---
func (k *RsaKey) UnmarshalYAML(unmarshal func(interface{}) error) error {

	// Cannot use embedded 'Key' struct
	// https://github.com/go-yaml/yaml/issues/263
	type YamlKey struct {
		Metadata      KeyMetadata `yaml:"Metadata"`
		PrivateKeyPem string      `yaml:"PrivateKeyPem"`
	}

	yk := YamlKey{}
	if err := unmarshal(&yk); err != nil {
		return &UnmarshalYAMLError{err.Error()}
	}

	k.Type = TypeRsa
	k.Metadata = yk.Metadata
	defaultSeededKeyMetadata(&k.Metadata)

	pemDecoded, _ := pem.Decode([]byte(yk.PrivateKeyPem))
	if pemDecoded == nil {
		return &UnmarshalYAMLError{fmt.Sprintf("Unable to decode pem of key %s check the YAML.\n", k.Metadata.KeyId)}
	}

	parseResult, pkcsParseError := x509.ParsePKCS8PrivateKey(pemDecoded.Bytes)
	if pkcsParseError != nil {
		return &UnmarshalYAMLError{fmt.Sprintf("Unable to decode pem of key %s, Ensure it is in PKCS8 format with no password: %s.\n", k.Metadata.KeyId, pkcsParseError)}
	}

	key := parseResult.(*rsa.PrivateKey)
	k.PrivateKey = RsaPrivateKey(*key)
	bitLen := key.N.BitLen()
	switch bitLen {
	case 2048:
		k.Metadata.KeySpec = SpecRsa2048
	case 3072:
		k.Metadata.KeySpec = SpecRsa3072
	case 4096:
		k.Metadata.KeySpec = SpecRsa4096
	default:
		return &UnmarshalYAMLError{
			fmt.Sprintf(
				"RSA Keysize must be one of (2048,3072,4096) bits. %d bits found for key %s.\n",
				bitLen, k.Metadata.KeyId),
		}
	}

	k.Metadata.CustomerMasterKeySpec = k.Metadata.KeySpec

	switch k.Metadata.KeyUsage {
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
		return &UnmarshalYAMLError{
			fmt.Sprintf(
				"KeyUsage must be one of (%s,%s). It is mandatory for RSA keys.\n", UsageEncryptDecrypt, UsageSignVerify),
		}
	}
	return nil
}
