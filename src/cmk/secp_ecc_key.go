package cmk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"math/big"
	"os"
)

// SecpEccPrivateKey is a newtype wrapper to manage JSON Marshaling
type SecpEccPrivateKey ecdsa.PrivateKey

type SecpEccKey struct {
	BaseKey
	PrivateKey SecpEccPrivateKey
}

type SecpSignature struct {
	R, S *big.Int
}

type asn1EcSig struct {
	R *big.Int
	S *big.Int
}

func NewSecpEccKey(spec CustomerMasterKeySpec, metadata KeyMetadata, policy string) (*SecpEccKey, error) {

	if spec != SpecEccSecgP256K1 {
		return nil, errors.New("key spec error")
	}

	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, err
	}

	//---

	k := &SecpEccKey{
		PrivateKey: SecpEccPrivateKey(*privateKey),
	}

	k.Type = TypeSecpEcc
	k.Metadata = metadata
	k.Policy = policy

	//---

	k.Metadata.KeyUsage = UsageSignVerify
	k.Metadata.CustomerMasterKeySpec = spec

	k.Metadata.SigningAlgorithms = []SigningAlgorithm{SigningAlgorithmEcdsaSha256}

	return k, nil
}

//----------------------------------------------------

func (k *SecpEccKey) GetArn() string {
	return k.GetMetadata().Arn
}

func (k *SecpEccKey) GetPolicy() string {
	return k.Policy
}

func (k *SecpEccKey) GetKeyType() KeyType {
	return k.Type
}

func (k *SecpEccKey) GetMetadata() *KeyMetadata {
	return &k.Metadata
}

//----------------------------------------------------

func (k *SecpEccKey) Sign(digest []byte, algorithm SigningAlgorithm) ([]byte, error) {
	//--------------------------
	// Check the requested Signing Algorithm is supported by this key
	if algorithm != SigningAlgorithmEcdsaSha256 {
		return []byte{}, &InvalidSigningAlgorithm{}
	}

	//--------------------------
	// Check the digest is the correct length for the algorithm
	if len(digest) != (256 / 8) {
		return []byte{}, &InvalidDigestLength{}
	}

	//---

	key := crypto.FromECDSA((*ecdsa.PrivateKey)(&k.PrivateKey))

	signatureBytes, err := secp256k1.Sign(digest, key)
	if err != nil {
		return []byte{}, err
	}

	r := new(big.Int).SetBytes(signatureBytes[:32])
	s := new(big.Int).SetBytes(signatureBytes[32:64])

	return asn1.Marshal(asn1EcSig{
		R: r,
		S: s,
	})
}

func (k *SecpEccKey) HashAndSign(message []byte, algorithm SigningAlgorithm) ([]byte, error) {

	digest, err := hashMessage(message, algorithm)
	if err != nil {
		return []byte{}, err
	}

	return k.Sign(digest, algorithm)
}

//----------------------------------------------------

func (k *SecpEccKey) Verify(signature []byte, digest []byte, algorithm SigningAlgorithm) (bool, error) {

	if algorithm != SigningAlgorithmEcdsaSha256 {
		return false, fmt.Errorf("invalid signing algorithm")
	}

	ecdsaSignature := ecdsaSignature{}

	_, err := asn1.Unmarshal(signature, &ecdsaSignature)
	if err != nil {
		return false, err
	}

	key := ecdsa.PrivateKey(k.PrivateKey)

	valid := ecdsa.Verify(&key.PublicKey, digest, ecdsaSignature.R, ecdsaSignature.S)

	return valid, nil
}

func (k *SecpEccKey) HashAndVerify(signature []byte, message []byte, algorithm SigningAlgorithm) (bool, error) {

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
func (k *SecpEccPrivateKey) UnmarshalJSON(data []byte) error {
	var pk ecdsa.PrivateKey
	pk.Curve = &elliptic.CurveParams{}

	err := json.Unmarshal(data, &pk)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
		return err
	}

	*k = SecpEccPrivateKey(pk)
	return nil
}

// UnmarshalYAML constructs key from YAML (seeding)
func (k *SecpEccKey) UnmarshalYAML(unmarshal func(interface{}) error) error {

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

	k.Type = TypeSecpEcc
	k.Metadata = yk.Metadata
	defaultSeededKeyMetadata(&k.Metadata)
	pemDecoded, _ := pem.Decode([]byte(yk.PrivateKeyPem))
	if pemDecoded == nil {
		return &UnmarshalYAMLError{fmt.Sprintf("Unable to decode pem of key %s check the YAML.\n", k.Metadata.KeyId)}
	}

	parseResult, pkcsParseError := x509.ParseECPrivateKey(pemDecoded.Bytes)
	if pkcsParseError != nil {
		return &UnmarshalYAMLError{fmt.Sprintf("Unable to decode pem of key %s, Ensure it is in PKCS8 format with no password: %s.\n", k.Metadata.KeyId, pkcsParseError)}
	}

	k.PrivateKey = SecpEccPrivateKey(*parseResult)
	k.Metadata.CustomerMasterKeySpec = SpecEccNistP256
	k.Metadata.SigningAlgorithms = []SigningAlgorithm{SigningAlgorithmEcdsaSha256}

	if k.Metadata.KeyUsage != UsageSignVerify {
		return &UnmarshalYAMLError{
			fmt.Sprintf(
				"Only KeyUsage of (%s) supported for EC keys.\n", UsageSignVerify),
		}
	}
	return nil
}
