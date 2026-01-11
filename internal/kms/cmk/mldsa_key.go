package cmk

import (
	"encoding/pem"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/nsmithuk/local-kms/internal/kms/cmk/x509mldsa"
	"github.com/nsmithuk/local-kms/internal/kms/kmserr"
	"github.com/nsmithuk/ml-dsa/mldsa44"
	"github.com/nsmithuk/ml-dsa/mldsa65"
	"github.com/nsmithuk/ml-dsa/mldsa87"
	mldsa "github.com/nsmithuk/ml-dsa/types"
)

type MlDsaKey struct {
	BaseKey
	PrivateKeyBytes []byte
}

//------------------------------------------------

func NewMlDsaKey(metadata types.KeyMetadata, policy string) (*MlDsaKey, error) {

	switch metadata.KeyUsage {
	case types.KeyUsageTypeSignVerify:

		metadata.SigningAlgorithms = []types.SigningAlgorithmSpec{
			types.SigningAlgorithmSpecMlDsaShake256,
		}

	case "":
		return nil, kmserr.NewValidation(kmserr.CauseValidationError, "You must specify a KeyUsage value when KeySpec is %s", metadata.KeySpec)
	default:
		return nil, kmserr.NewValidation(kmserr.CauseUnsupportedOperationException, "KeyUsage %s is not compatible with KeySpec %s", metadata.KeyUsage, metadata.KeySpec)
	}

	return &MlDsaKey{
		BaseKey: BaseKey{Metadata: metadata, Policy: policy, KeyType: TypeMlDsaKey},
	}, nil
}

func (k *MlDsaKey) ApplyNewKeyMaterial() error {

	var sk mldsa.PrivateKey
	var err error

	switch k.GetMetadata().KeySpec {
	case types.KeySpecMlDsa44:
		_, sk, err = mldsa44.GenerateKeyPair(nil)
	case types.KeySpecMlDsa65:
		_, sk, err = mldsa65.GenerateKeyPair(nil)
	case types.KeySpecMlDsa87:
		_, sk, err = mldsa87.GenerateKeyPair(nil)
	default:
		return fmt.Errorf("unexpected KeySpec %s", k.GetMetadata().KeySpec)
	}

	if err != nil {
		return err
	}

	k.PrivateKeyBytes = sk.EncodeExpanded()

	return nil
}

func (k *MlDsaKey) ApplySeedingKeyMaterial(material SeedingKeyMaterial) error {
	if material.PrivateKeyPem == nil {
		return fmt.Errorf("PrivateKeyPem is required for %s", k.KeyType)
	}

	pemDecoded, _ := pem.Decode([]byte(*material.PrivateKeyPem))
	if pemDecoded == nil {
		return fmt.Errorf("Failed to decode private key PEM for %s", k.GetArn())
	}

	key, err := x509mldsa.ParsePKCS8PrivateKey(pemDecoded.Bytes)
	if err != nil {
		return err
	}

	keySpec := k.GetMetadata().KeySpec

	switch sk := key.(type) {
	case *mldsa44.PrivateKey:
		if keySpec != types.KeySpecMlDsa44 {
			return fmt.Errorf("KeySpec %s is not compatible with detected key type mldsa44", keySpec)
		}
		k.PrivateKeyBytes = sk.EncodeExpanded()
	case *mldsa65.PrivateKey:
		if keySpec != types.KeySpecMlDsa65 {
			return fmt.Errorf("KeySpec %s is not compatible with detected key type mldsa65", keySpec)
		}
		k.PrivateKeyBytes = sk.EncodeExpanded()
	case *mldsa87.PrivateKey:
		if keySpec != types.KeySpecMlDsa87 {
			return fmt.Errorf("KeySpec %s is not compatible with detected key type mldsa87", keySpec)
		}
		k.PrivateKeyBytes = sk.EncodeExpanded()
	default:
		return fmt.Errorf("Unknown key type %T", key)
	}

	return nil
}

//-----

func (k *MlDsaKey) PublicKey() (mldsa.PublicKey, error) {
	sk, err := k.PrivateKey()
	if err != nil {
		return nil, err
	}

	return sk.PublicKey(), nil
}

func (k *MlDsaKey) PrivateKey() (mldsa.PrivateKey, error) {
	var key mldsa.PrivateKey
	var err error

	switch k.GetMetadata().KeySpec {
	case types.KeySpecMlDsa44:
		key, err = mldsa44.PrivateKeyFromExpanded(k.PrivateKeyBytes)
	case types.KeySpecMlDsa65:
		key, err = mldsa65.PrivateKeyFromExpanded(k.PrivateKeyBytes)
	case types.KeySpecMlDsa87:
		key, err = mldsa87.PrivateKeyFromExpanded(k.PrivateKeyBytes)
	default:
		return nil, fmt.Errorf("unexpected KeySpec %s", k.GetMetadata().KeySpec)
	}

	if err != nil {
		return nil, err
	}

	return key, nil
}
