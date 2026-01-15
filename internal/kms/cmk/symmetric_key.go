package cmk

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/nsmithuk/local-kms/internal/kms/kmserr"
	"gopkg.in/yaml.v3"
)

type SymmetricBackingKey struct {
	Material [32]byte
}

func NewSymmetricBackingKey() SymmetricBackingKey {
	var key [32]byte
	copy(key[:], GenerateRandomData(32))
	return SymmetricBackingKey{
		Material: key,
	}
}

func (bk SymmetricBackingKey) MaterialId() string {
	hash := sha256.Sum256(bk.Material[:])
	return hex.EncodeToString(hash[:])
}

//--------------------------------

type SymmetricKey struct {
	BaseKey
	NextKeyRotation      time.Time
	RotationPeriodInDays int32
	ManualKeyRotations   uint8
	BackingKeys          map[string]SymmetricBackingKey
}

func NewSymmetricKey(metadata types.KeyMetadata, policy string) (*SymmetricKey, error) {

	switch metadata.KeyUsage {
	case "":
		metadata.KeyUsage = types.KeyUsageTypeEncryptDecrypt
		fallthrough

	case types.KeyUsageTypeEncryptDecrypt:
		metadata.EncryptionAlgorithms = []types.EncryptionAlgorithmSpec{
			types.EncryptionAlgorithmSpecSymmetricDefault,
		}

	default:
		return nil, kmserr.NewValidation(kmserr.CauseUnsupportedOperationException, "KeyUsage %s is not compatible with KeySpec %s", metadata.KeyUsage, metadata.KeySpec)
	}

	//---

	return &SymmetricKey{
		BaseKey:     BaseKey{Metadata: metadata, Policy: policy, KeyType: TypeSymmetricKey},
		BackingKeys: make(map[string]SymmetricBackingKey),
	}, nil
}

func (k *SymmetricKey) ApplyNewKeyMaterial() error {
	key := NewSymmetricBackingKey()
	materialId := key.MaterialId()

	k.BackingKeys[materialId] = key
	k.Metadata.CurrentKeyMaterialId = &materialId

	return nil
}

func (k *SymmetricKey) ApplySeedingKeyMaterial(material SeedingKeyMaterial) error {
	if material.BackingKeys == nil || len(material.BackingKeys) < 1 {
		return fmt.Errorf("One or more BackingKeys are required for %s", k.KeyType)
	}

	for _, backingKey := range material.BackingKeys {
		keyBytes, err := hex.DecodeString(backingKey)
		if err != nil {
			return err
		}
		if len(keyBytes) != 32 {
			return fmt.Errorf("BackingKey %s is not a valid SymmetricKey - it must be exactly 32 bytes", backingKey)
		}

		var keyArr [32]byte
		copy(keyArr[:], keyBytes)
		key := SymmetricBackingKey{
			Material: keyArr,
		}

		materialId := key.MaterialId()
		k.BackingKeys[materialId] = key

		// Results in the last key being set as the current material.
		k.Metadata.CurrentKeyMaterialId = &materialId
	}

	return nil
}

//--------------------------------

func (k *SymmetricKey) ApplyImportedKeyMaterial(material []byte, passedMaterialId *string) error {
	if len(material) != 32 {
		return fmt.Errorf("material must be exactly 32 bytes")
	}

	var keyArr [32]byte
	copy(keyArr[:], material)
	key := SymmetricBackingKey{
		Material: keyArr,
	}

	newMaterialId := key.MaterialId()
	currentMaterialId := k.GetMetadata().CurrentKeyMaterialId

	if currentMaterialId != nil {
		// Then it's a re-import
		if passedMaterialId == nil {
			return fmt.Errorf("passed materialId must be set for a re-import")
		}
		if *currentMaterialId != *passedMaterialId {
			return fmt.Errorf("the passed material ID must match the current material ID for re-import")
		}
		if *currentMaterialId != newMaterialId {
			return fmt.Errorf("the passed key must be exactly the same as the previous for a re-improt")
		}
	} else if passedMaterialId != nil {
		// We should not have a passed value if it's not a re-import
		return fmt.Errorf("passed material id should not be nil for a key re-import")
	}

	//---

	k.BackingKeys[newMaterialId] = key
	k.Metadata.CurrentKeyMaterialId = &newMaterialId

	return nil
}

//--------------------------------

func (k *SymmetricKey) RotateIfNeeded() bool {

	if k.RotationPeriodInDays > 0 && k.NextKeyRotation.Before(time.Now()) {

		_ = k.ApplyNewKeyMaterial()
		k.NextKeyRotation = time.Now().AddDate(0, 0, int(k.RotationPeriodInDays))

		// The key did rotate
		return true
	}

	// The key did not rotate
	return false
}

func (k *SymmetricKey) UnmarshalYAML(value *yaml.Node) error {
	return nil
}
