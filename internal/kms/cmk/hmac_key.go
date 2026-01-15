package cmk

import (
	"encoding/hex"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/nsmithuk/local-kms/internal/kms/kmserr"
)

type HmacKey struct {
	BaseKey
	PrivateKey []byte
}

func NewHmacKey(metadata types.KeyMetadata, policy string) (*HmacKey, error) {

	switch metadata.KeyUsage {
	case types.KeyUsageTypeGenerateVerifyMac:

		switch metadata.KeySpec {
		case types.KeySpecHmac224:
			metadata.MacAlgorithms = []types.MacAlgorithmSpec{types.MacAlgorithmSpecHmacSha224}
		case types.KeySpecHmac256:
			metadata.MacAlgorithms = []types.MacAlgorithmSpec{types.MacAlgorithmSpecHmacSha256}
		case types.KeySpecHmac384:
			metadata.MacAlgorithms = []types.MacAlgorithmSpec{types.MacAlgorithmSpecHmacSha384}
		case types.KeySpecHmac512:
			metadata.MacAlgorithms = []types.MacAlgorithmSpec{types.MacAlgorithmSpecHmacSha512}
		}

	case "":
		return nil, kmserr.NewValidation(kmserr.CauseValidationError, "You must specify a KeyUsage value when KeySpec is %s", metadata.KeySpec)
	default:
		return nil, kmserr.NewValidation(kmserr.CauseUnsupportedOperationException, "KeyUsage %s is not compatible with KeySpec %s", metadata.KeyUsage, metadata.KeySpec)
	}

	return &HmacKey{
		BaseKey: BaseKey{Metadata: metadata, Policy: policy, KeyType: TypeHmacKey},
	}, nil
}

func (k *HmacKey) ApplyNewKeyMaterial() error {

	switch k.GetMetadata().KeySpec {
	case types.KeySpecHmac224:
		k.PrivateKey = GenerateRandomData(224 / 8)
	case types.KeySpecHmac256:
		k.PrivateKey = GenerateRandomData(256 / 8)
	case types.KeySpecHmac384:
		k.PrivateKey = GenerateRandomData(384 / 8)
	case types.KeySpecHmac512:
		k.PrivateKey = GenerateRandomData(512 / 8)
	}

	return nil
}

func (k *HmacKey) ApplySeedingKeyMaterial(material SeedingKeyMaterial) error {
	if material.BackingKeys == nil || len(material.BackingKeys) != 1 {
		return fmt.Errorf("Exactly one BackingKey is required for %s", k.KeyType)
	}

	keyBytes, err := hex.DecodeString(material.BackingKeys[0])
	if err != nil {
		return err
	}

	keySpec := k.GetMetadata().KeySpec

	switch len(keyBytes) {
	case 224 / 8:
		if keySpec != types.KeySpecHmac224 {
			return fmt.Errorf("KeySpec %s is not compatible with a %d bit key", keySpec, len(keyBytes)*8)
		}
	case 256 / 8:
		if keySpec != types.KeySpecHmac256 {
			return fmt.Errorf("KeySpec %s is not compatible with a %d bit key", keySpec, len(keyBytes)*8)
		}
	case 384 / 8:
		if keySpec != types.KeySpecHmac384 {
			return fmt.Errorf("KeySpec %s is not compatible with a %d bit key", keySpec, len(keyBytes)*8)
		}
	case 512 / 8:
		if keySpec != types.KeySpecHmac512 {
			return fmt.Errorf("KeySpec %s is not compatible with a %d bit key", keySpec, len(keyBytes)*8)
		}
	default:
		return fmt.Errorf("unknown key length %d", len(material.BackingKeys))
	}

	k.PrivateKey = keyBytes

	return nil
}

func (k *HmacKey) ApplyImportedKeyMaterial(material []byte, _ *string, _ types.ImportType) error {
	keySpec := k.GetMetadata().KeySpec

	switch len(material) {
	case 224 / 8:
		if keySpec != types.KeySpecHmac224 {
			return fmt.Errorf("KeySpec %s is not compatible with a %d bit key", keySpec, len(material)*8)
		}
	case 256 / 8:
		if keySpec != types.KeySpecHmac256 {
			return fmt.Errorf("KeySpec %s is not compatible with a %d bit key", keySpec, len(material)*8)
		}
	case 384 / 8:
		if keySpec != types.KeySpecHmac384 {
			return fmt.Errorf("KeySpec %s is not compatible with a %d bit key", keySpec, len(material)*8)
		}
	case 512 / 8:
		if keySpec != types.KeySpecHmac512 {
			return fmt.Errorf("KeySpec %s is not compatible with a %d bit key", keySpec, len(material)*8)
		}
	default:
		return fmt.Errorf("unknown key length %d", len(material))
	}

	k.PrivateKey = material

	return nil
}

func (k *HmacKey) DeleteImportedKeyMaterial(*string) error {
	metadata := k.GetMetadata()
	if metadata.Origin != types.OriginTypeExternal {
		return fmt.Errorf("Cannot delete key that is not an external key")
	}

	k.PrivateKey = nil

	return nil
}
