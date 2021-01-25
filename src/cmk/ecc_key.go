package cmk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
)

// We create our own type to manage JSON Marshaling
type EcdsaPrivateKey ecdsa.PrivateKey

type EccKey struct {
	BaseKey
	PrivateKey EcdsaPrivateKey
}

type ecdsaSignature struct {
	R, S *big.Int
}

func NewEccKey(spec CustomerMasterKeySpec, metadata KeyMetadata, policy string) (*EccKey, error) {

	var curve elliptic.Curve

	switch spec {
	case SpecEccNistP256:
		curve = elliptic.P256()
	case SpecEccNistP384:
		curve = elliptic.P384()
	case SpecEccNistP521:
		curve = elliptic.P521()
	default:
		return nil, errors.New("key spec error")
	}

	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}

	//---

	k := &EccKey{
		PrivateKey: EcdsaPrivateKey(*privateKey),
	}

	k.Type = TypeEcc
	k.Metadata = metadata
	k.Policy = policy

	//---

	k.Metadata.KeyUsage = UsageSignVerify
	k.Metadata.CustomerMasterKeySpec = spec

	switch spec {
	case SpecEccNistP256:
		k.Metadata.SigningAlgorithms = []SigningAlgorithm{SigningAlgorithmEcdsaSha256}
	case SpecEccNistP384:
		k.Metadata.SigningAlgorithms = []SigningAlgorithm{SigningAlgorithmEcdsaSha384}
	case SpecEccNistP521:
		k.Metadata.SigningAlgorithms = []SigningAlgorithm{SigningAlgorithmEcdsaSha512}
	default:
		return nil, errors.New("signing algorithm error")
	}

	return k, nil
}

//----------------------------------------------------

func (k *EccKey) GetArn() string {
	return k.GetMetadata().Arn
}

func (k *EccKey) GetPolicy() string {
	return k.Policy
}

func (k *EccKey) GetKeyType() KeyType {
	return k.Type
}

func (k *EccKey) GetMetadata() *KeyMetadata {
	return &k.Metadata
}

//----------------------------------------------------

func (k *EccKey) Sign(digest []byte, algorithm SigningAlgorithm) ([]byte, error) {

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
	// Check the digest is the correct length for the algorithm

	switch algorithm {
	case SigningAlgorithmEcdsaSha256:
		if len(digest) != (256 / 8) {
			return []byte{}, &InvalidDigestLength{}
		}
	case SigningAlgorithmEcdsaSha384:
		if len(digest) != (384 / 8) {
			return []byte{}, &InvalidDigestLength{}
		}
	case SigningAlgorithmEcdsaSha512:
		if len(digest) != (512 / 8) {
			return []byte{}, &InvalidDigestLength{}
		}
	default:
		return []byte{}, errors.New("unknown signing algorithm")
	}

	//---

	key := ecdsa.PrivateKey(k.PrivateKey)

	r, s, err := ecdsa.Sign(rand.Reader, &key, digest)
	if err != nil {
		return []byte{}, err
	}

	return asn1.Marshal(ecdsaSignature{r, s})
}

func (k *EccKey) HashAndSign(message []byte, algorithm SigningAlgorithm) ([]byte, error) {

	digest, err := hashMessage(message, algorithm)
	if err != nil {
		return []byte{}, err
	}

	return k.Sign(digest, algorithm)
}

//----------------------------------------------------

func (k *EccKey) Verify(signature []byte, digest []byte, algorithm SigningAlgorithm) (bool, error) {

	ecdsaSignature := ecdsaSignature{}

	_, err := asn1.Unmarshal(signature, &ecdsaSignature)
	if err != nil {
		return false, err
	}

	key := ecdsa.PrivateKey(k.PrivateKey)

	valid := ecdsa.Verify(&key.PublicKey, digest, ecdsaSignature.R, ecdsaSignature.S)

	return valid, nil
}

func (k *EccKey) HashAndVerify(signature []byte, message []byte, algorithm SigningAlgorithm) (bool, error) {

	digest, err := hashMessage(message, algorithm)
	if err != nil {
		return false, err
	}

	return k.Verify(signature, digest, algorithm)
}

//----------------------------------------------------

/*
	ecdsa.PrivateKey.Curve is an interface type, so we need to
	Unmarshal it ourselves to set the concrete type.
*/
func (k *EcdsaPrivateKey) UnmarshalJSON(data []byte) error {
	var pk ecdsa.PrivateKey
	pk.Curve = &elliptic.CurveParams{}

	err := json.Unmarshal(data, &pk)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
		return err
	}

	switch pk.Curve.Params().Name {
	case "P-256":
		pk.Curve = elliptic.P256()
	case "P-384":
		pk.Curve = elliptic.P384()
	case "P-521":
		pk.Curve = elliptic.P521()
	}

	*k = EcdsaPrivateKey(pk)
	return nil
}

//----------------------------------------------------
// Construct key from YAML (seeding)
//---
func (k *EccKey) UnmarshalYAML(unmarshal func(interface{}) error) error {

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

	k.Type = TypeEcc
	k.Metadata = yk.Metadata
	pemDecoded, _ := pem.Decode([]byte(yk.PrivateKeyPem))
	if pemDecoded == nil {
		return &UnmarshalYAMLError{fmt.Sprintf("Unable to decode pem of key %s check the YAML.\n", k.Metadata.KeyId)}
	}

	parseResult, pkcsParseError := x509.ParseECPrivateKey(pemDecoded.Bytes)
	if pkcsParseError != nil {
		return &UnmarshalYAMLError{fmt.Sprintf("Unable to decode pem of key %s, Ensure it is in PKCS8 format with no password: %s.\n", k.Metadata.KeyId, pkcsParseError)}
	}

	k.PrivateKey = EcdsaPrivateKey(*parseResult)
	var bitLen = parseResult.Curve.Params().BitSize

	switch bitLen {
	case 256:
		k.Metadata.CustomerMasterKeySpec = SpecEccNistP256
		k.Metadata.SigningAlgorithms = []SigningAlgorithm{SigningAlgorithmEcdsaSha256}
	case 384:
		k.Metadata.CustomerMasterKeySpec = SpecEccNistP384
		k.Metadata.SigningAlgorithms = []SigningAlgorithm{SigningAlgorithmEcdsaSha384}
	case 521:
		k.Metadata.CustomerMasterKeySpec = SpecEccNistP521
		k.Metadata.SigningAlgorithms = []SigningAlgorithm{SigningAlgorithmEcdsaSha512}
	default:
		return &UnmarshalYAMLError{
			fmt.Sprintf(
				"EC Keysize must be one of (256,384,521) bits. %d bits found for key %s.\n",
				bitLen, k.Metadata.KeyId),
		}
	}

	if k.Metadata.KeyUsage != UsageSignVerify {
		return &UnmarshalYAMLError{
			fmt.Sprintf(
				"Only KeyUsage of (%s) supported for EC keys.\n", UsageSignVerify),
		}
	}
	return nil
}
