package cmk

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/nsmithuk/local-kms/internal/kms/kmserr"
)

type Ed25519Key struct {
	BaseKey
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

func NewEd25519Key(metadata types.KeyMetadata, policy string) (*Ed25519Key, error) {

	switch metadata.KeyUsage {
	case types.KeyUsageTypeSignVerify:

		metadata.SigningAlgorithms = []types.SigningAlgorithmSpec{
			types.SigningAlgorithmSpecEd25519Sha512,
			types.SigningAlgorithmSpecEd25519PhSha512,
		}

	case "":
		return nil, kmserr.NewValidation(kmserr.CauseValidationError, "You must specify a KeyUsage value when KeySpec is %s", metadata.KeySpec)
	default:
		return nil, kmserr.NewValidation(kmserr.CauseUnsupportedOperationException, "KeyUsage %s is not compatible with KeySpec %s", metadata.KeyUsage, metadata.KeySpec)
	}

	return &Ed25519Key{
		BaseKey: BaseKey{Metadata: metadata, Policy: policy, KeyType: TypeEd25519Key},
	}, nil
}

func (k *Ed25519Key) ApplyNewKeyMaterial() error {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}

	k.PublicKey = pub
	k.PrivateKey = priv

	return nil
}

func (k *Ed25519Key) ApplySeedingKeyMaterial(material SeedingKeyMaterial) error {
	if material.PrivateKeyPem == nil {
		return fmt.Errorf("PrivateKeyPem is required for %s", k.KeyType)
	}

	pemDecoded, _ := pem.Decode([]byte(*material.PrivateKeyPem))
	if pemDecoded == nil {
		return fmt.Errorf("Failed to decode private key PEM for %s", k.GetArn())
	}

	key, err := x509.ParsePKCS8PrivateKey(pemDecoded.Bytes)
	if err != nil {
		return err
	}

	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return fmt.Errorf("PEM is not an Ed25519PrivateKey")
	}

	k.PrivateKey = priv
	k.PublicKey = priv.Public().(ed25519.PublicKey)

	return nil
}

func (k *Ed25519Key) ApplyImportedKeyMaterial(material []byte, _ *string, _ types.ImportType) error {
	pk, err := x509.ParsePKCS8PrivateKey(material)
	if err != nil {
		return err
	}

	k.PrivateKey = pk.(ed25519.PrivateKey)
	k.PublicKey = k.PrivateKey.Public().(ed25519.PublicKey)

	return nil
}

func (k *Ed25519Key) DeleteImportedKeyMaterial(*string) error {
	metadata := k.GetMetadata()
	if metadata.Origin != types.OriginTypeExternal {
		return fmt.Errorf("Cannot delete key that is not an external key")
	}

	k.PrivateKey = nil
	k.PublicKey = nil

	return nil
}
