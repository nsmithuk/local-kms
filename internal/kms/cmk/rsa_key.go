package cmk

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/nsmithuk/local-kms/internal/kms/kmserr"
)

type RsaPrivateKey rsa.PrivateKey

type RsaKey struct {
	BaseKey
	PrivateKey RsaPrivateKey
}

func NewRsaKey(metadata types.KeyMetadata, policy string) (*RsaKey, error) {

	switch metadata.KeyUsage {
	case types.KeyUsageTypeSignVerify:

		metadata.SigningAlgorithms = []types.SigningAlgorithmSpec{
			types.SigningAlgorithmSpecRsassaPssSha256,
			types.SigningAlgorithmSpecRsassaPssSha384,
			types.SigningAlgorithmSpecRsassaPssSha512,
			types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
			types.SigningAlgorithmSpecRsassaPkcs1V15Sha384,
			types.SigningAlgorithmSpecRsassaPkcs1V15Sha512,
		}

	case types.KeyUsageTypeEncryptDecrypt:

		metadata.EncryptionAlgorithms = []types.EncryptionAlgorithmSpec{
			types.EncryptionAlgorithmSpecRsaesOaepSha1,
			types.EncryptionAlgorithmSpecRsaesOaepSha256,
		}

	case "":
		return nil, kmserr.NewValidation(kmserr.CauseValidationError, "You must specify a KeyUsage value when KeySpec is %s", metadata.KeySpec)
	default:
		return nil, kmserr.NewValidation(kmserr.CauseUnsupportedOperationException, "KeyUsage %s is not compatible with KeySpec %s", metadata.KeyUsage, metadata.KeySpec)
	}

	//---

	return &RsaKey{
		BaseKey: BaseKey{Metadata: metadata, Policy: policy, KeyType: TypeRsaKey},
	}, nil
}

func (k *RsaKey) ApplyNewKeyMaterial() error {

	var bits int

	switch k.GetMetadata().KeySpec {
	case types.KeySpecRsa2048:
		bits = 2048
	case types.KeySpecRsa3072:
		bits = 3072
	case types.KeySpecRsa4096:
		bits = 4096
	default:
		return errors.New("key spec error")
	}

	//---

	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}

	k.PrivateKey = RsaPrivateKey(*privateKey)

	return nil
}

func (k *RsaKey) ApplySeedingKeyMaterial(material SeedingKeyMaterial) error {
	if material.PrivateKeyPem == nil {
		return fmt.Errorf("PrivateKeyPem is required for %s", k.KeyType)
	}

	pemDecoded, _ := pem.Decode([]byte(*material.PrivateKeyPem))
	if pemDecoded == nil {
		return fmt.Errorf("Failed to decode private key PEM for %s", k.GetArn())
	}

	rsaPrivateKeyUntyped, err := x509.ParsePKCS8PrivateKey(pemDecoded.Bytes)
	if err != nil {
		return err
	}

	rsaPrivateKey, ok := rsaPrivateKeyUntyped.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("Failed to parse private key for %s", k.GetArn())
	}

	bitLen := rsaPrivateKey.N.BitLen()
	keySpec := k.GetMetadata().KeySpec

	switch bitLen {
	case 2048:
		if keySpec != types.KeySpecRsa2048 {
			return fmt.Errorf("KeySpec %s is not compatible with a %d bit key", keySpec, bitLen)
		}
	case 3072:
		if keySpec != types.KeySpecRsa3072 {
			return fmt.Errorf("KeySpec %s is not compatible with a %d bit key", keySpec, bitLen)
		}
	case 4096:
		if keySpec != types.KeySpecRsa4096 {
			return fmt.Errorf("KeySpec %s is not compatible with a %d bit key", keySpec, bitLen)
		}
	default:
		return fmt.Errorf("Unknown key length %d", bitLen)
	}

	k.PrivateKey = RsaPrivateKey(*rsaPrivateKey)

	return nil
}

//-----------------------------------

func (k *RsaKey) ApplyImportedKeyMaterial(material []byte, _ *string, _ types.ImportType) error {
	pk, err := x509.ParsePKCS8PrivateKey(material)
	if err != nil {
		return err
	}

	k.PrivateKey = RsaPrivateKey(*pk.(*rsa.PrivateKey))

	return nil
}

func (k *RsaKey) DeleteImportedKeyMaterial(*string) error {
	metadata := k.GetMetadata()
	if metadata.Origin != types.OriginTypeExternal {
		return fmt.Errorf("Cannot delete key that is not an external key")
	}

	k.PrivateKey = RsaPrivateKey{}

	return nil
}
