package cmk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/nsmithuk/local-kms/internal/kms/cmk/x509ecc"
	"github.com/nsmithuk/local-kms/internal/kms/kmserr"
)

type EcdsaPrivateKey ecdsa.PrivateKey

type EcdsaKey struct {
	BaseKey
	PrivateKey EcdsaPrivateKey
}

func NewEcdsaKey(metadata types.KeyMetadata, policy string) (*EcdsaKey, error) {

	switch metadata.KeyUsage {
	case types.KeyUsageTypeSignVerify:
		switch metadata.KeySpec {
		case types.KeySpecEccNistP256:
			metadata.SigningAlgorithms = []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEcdsaSha256}
		case types.KeySpecEccNistP384:
			metadata.SigningAlgorithms = []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEcdsaSha384}
		case types.KeySpecEccNistP521:
			metadata.SigningAlgorithms = []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEcdsaSha512}
		case types.KeySpecEccSecgP256k1:
			metadata.SigningAlgorithms = []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEcdsaSha256}
		}

	case types.KeyUsageTypeKeyAgreement:
		if metadata.KeySpec == types.KeySpecEccSecgP256k1 {
			return nil, kmserr.NewValidation(kmserr.CauseUnsupportedOperationException, "KeyUsage %s is not compatible with KeySpec %s", metadata.KeyUsage, metadata.KeySpec)
		}

		metadata.KeyAgreementAlgorithms = []types.KeyAgreementAlgorithmSpec{types.KeyAgreementAlgorithmSpecEcdh}

	case "":
		return nil, kmserr.NewValidation(kmserr.CauseValidationError, "You must specify a KeyUsage value when KeySpec is %s", metadata.KeySpec)
	default:
		return nil, kmserr.NewValidation(kmserr.CauseUnsupportedOperationException, "KeyUsage %s is not compatible with KeySpec %s", metadata.KeyUsage, metadata.KeySpec)
	}

	return &EcdsaKey{
		BaseKey: BaseKey{Metadata: metadata, Policy: policy, KeyType: TypeEcdsaKey},
	}, nil
}

func (k *EcdsaKey) ApplyNewKeyMaterial() error {

	var curve elliptic.Curve

	switch k.GetMetadata().KeySpec {
	case types.KeySpecEccNistP256:
		curve = elliptic.P256()
	case types.KeySpecEccNistP384:
		curve = elliptic.P384()
	case types.KeySpecEccNistP521:
		curve = elliptic.P521()
	case types.KeySpecEccSecgP256k1:
		curve = secp256k1.S256()
	}

	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return err
	}

	k.PrivateKey = EcdsaPrivateKey(*privateKey)

	return nil
}

func (k *EcdsaKey) ApplySeedingKeyMaterial(material SeedingKeyMaterial) error {
	if material.PrivateKeyPem == nil {
		return fmt.Errorf("PrivateKeyPem is required for %s", k.KeyType)
	}

	pemDecoded, _ := pem.Decode([]byte(*material.PrivateKeyPem))
	if pemDecoded == nil {
		return fmt.Errorf("Failed to decode private key PEM for %s", k.GetArn())
	}

	ecdsaPrivateKey, err := x509ecc.ParseECPrivateKey(pemDecoded.Bytes)
	if err != nil {
		return err
	}

	curve := ecdsaPrivateKey.Curve.Params().Name
	keySpec := k.GetMetadata().KeySpec

	switch curve {
	case "P-256":
		if keySpec != types.KeySpecEccNistP256 {
			return fmt.Errorf("KeySpec %s is not compatible with curve %s", keySpec, curve)
		}
	case "P-384":
		if keySpec != types.KeySpecEccNistP384 {
			return fmt.Errorf("KeySpec %s is not compatible with curve %s", keySpec, curve)
		}
	case "P-521":
		if keySpec != types.KeySpecEccNistP521 {
			return fmt.Errorf("KeySpec %s is not compatible with curve %s", keySpec, curve)
		}
	case "secp256k1":
		if keySpec != types.KeySpecEccSecgP256k1 {
			return fmt.Errorf("KeySpec %s is not compatible with curve %s", keySpec, curve)
		}
	default:
		return fmt.Errorf("Unknown curve '%s'", curve)
	}

	//---

	k.PrivateKey = EcdsaPrivateKey(*ecdsaPrivateKey)

	return nil
}

//-----

func (k *EcdsaKey) ApplyImportedKeyMaterial(material []byte, _ *string) error {
	pk, err := x509ecc.ParsePKCS8PrivateKey(material)
	if err != nil {
		return err
	}

	k.PrivateKey = EcdsaPrivateKey(*pk)

	return nil
}

//-----

func (k *EcdsaPrivateKey) MarshalJSON() ([]byte, error) {
	if k == nil || k.PublicKey.Curve == nil {
		return json.Marshal(nil)
	}

	data, err := x509ecc.MarshalPKCS8PrivateKey((*ecdsa.PrivateKey)(k))
	if err != nil {
		return nil, err
	}
	return json.Marshal(data)
}

func (k *EcdsaPrivateKey) UnmarshalJSON(data []byte) error {
	var d []byte
	err := json.Unmarshal(data, &d)

	if err != nil {
		return err
	}

	if d == nil {
		return nil
	}

	pk, err := x509ecc.ParsePKCS8PrivateKey(d)
	if err != nil {
		return err
	}

	*k = EcdsaPrivateKey(*pk)
	return nil
}
