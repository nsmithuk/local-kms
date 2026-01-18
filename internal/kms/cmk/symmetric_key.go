package cmk

import (
	"crypto/sha3"
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

func (bk SymmetricBackingKey) MaterialId(keyID string) string {
	m := append([]byte(keyID), bk.Material[:]...)
	return hex.EncodeToString(sha3.SumSHAKE256(m, 32))
}

//--------------------------------

type SymmetricKey struct {
	BaseKey
	NextKeyRotation      time.Time
	RotationPeriodInDays int32
	ManualKeyRotations   uint8
	BackingKeys          map[string]SymmetricBackingKey
	PreviousBackingKeys  map[string]SymmetricBackingKey
	PendingKey           *SymmetricBackingKey
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
	materialId := key.MaterialId(k.GetId())

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

		materialId := key.MaterialId(k.GetId())
		k.BackingKeys[materialId] = key

		// Results in the last key being set as the current material.
		k.Metadata.CurrentKeyMaterialId = &materialId
	}

	return nil
}

//--------------------------------

func (k *SymmetricKey) ApplyImportedKeyMaterial(material []byte, materialId *string, importType types.ImportType) error {
	if k.GetMetadata().Origin != types.OriginTypeExternal {
		return fmt.Errorf("Cannot import key that is not an external key")
	}
	if len(material) != 32 {
		return fmt.Errorf("material must be exactly 32 bytes")
	}

	var keyArr [32]byte
	copy(keyArr[:], material)
	key := SymmetricBackingKey{
		Material: keyArr,
	}

	newMaterialId := key.MaterialId(k.GetId())

	switch importType {
	case types.ImportTypeNewKeyMaterial:
		// For NEW material, callers must not specify KeyMaterialId.
		if materialId != nil && *materialId != "" {
			return fmt.Errorf("KeyMaterialId must not be specified for NEW_KEY_MATERIAL")
		}

		// First-ever import becomes current immediately.
		if len(k.BackingKeys) == 0 && k.PendingKey == nil && k.Metadata.CurrentKeyMaterialId == nil {
			k.BackingKeys[newMaterialId] = key
			k.Metadata.CurrentKeyMaterialId = &newMaterialId
			return nil
		}

		// Otherwise, stage as pending (only one pending at a time).
		if k.PendingKey != nil {
			return fmt.Errorf("key already has pending imported key material")
		}

		// Optional: prevent importing the same bytes as the current material as "new".
		if k.Metadata.CurrentKeyMaterialId != nil && *k.Metadata.CurrentKeyMaterialId == newMaterialId {
			return fmt.Errorf("cannot import NEW_KEY_MATERIAL: material already current")
		}

		k.PendingKey = &key

	case types.ImportTypeExistingKeyMaterial:
		// EXISTING requires a KeyMaterialId and it must match the computed ID.
		if materialId == nil || *materialId == "" {
			return fmt.Errorf("KeyMaterialId is required for EXISTING_KEY_MATERIAL")
		}
		if newMaterialId != *materialId {
			return fmt.Errorf("KeyMaterialId mismatch: computed %s does not match provided %s", newMaterialId, *materialId)
		}

		// Must be a previously-known material id (active or deleted).
		_, inActive := k.BackingKeys[*materialId]
		_, inDeleted := k.PreviousBackingKeys[*materialId]
		if !inActive && !inDeleted {
			return fmt.Errorf("materialId %s does not exist for this key", *materialId)
		}

		// Re-import restores the material bytes.
		k.BackingKeys[*materialId] = key
		delete(k.PreviousBackingKeys, *materialId)

		// If the key currently has no usable current material, make this current.
		// (Simplified model: always promote to current on re-import.)
		k.Metadata.CurrentKeyMaterialId = materialId

	default:
		return fmt.Errorf("unsupported ImportType %s", importType)
	}

	return nil
}

func (k *SymmetricKey) DeleteImportedKeyMaterial(passedMaterialId *string) error {
	metadata := k.GetMetadata()
	if metadata.Origin != types.OriginTypeExternal {
		return fmt.Errorf("Cannot delete key that is not an external key")
	}

	if k.PreviousBackingKeys == nil {
		k.PreviousBackingKeys = make(map[string]SymmetricBackingKey)
	}

	// Delete-all: move everything to PreviousBackingKeys.
	if passedMaterialId == nil {
		for id, key := range k.BackingKeys {
			k.PreviousBackingKeys[id] = key
		}
		k.BackingKeys = make(map[string]SymmetricBackingKey)
		return nil
	}

	key, found := k.BackingKeys[*passedMaterialId]
	if !found {
		return fmt.Errorf("materialId %s does not exist", *passedMaterialId)
	}

	k.PreviousBackingKeys[*passedMaterialId] = key
	delete(k.BackingKeys, *passedMaterialId)

	k.Metadata.CurrentKeyMaterialId = nil

	return nil
}

//--------------------------------

func (k *SymmetricKey) RotateKeyOnDemand() error {
	if k.ManualKeyRotations >= 10 {
		return kmserr.NewValidation(kmserr.CauseLimitExceededException, "key has already rotated 10 times")
	}

	if k.PendingKey != nil {
		// We use the pending key
		materialId := k.PendingKey.MaterialId(k.GetId())

		// Then we enable this
		k.BackingKeys[materialId] = *k.PendingKey
		k.Metadata.CurrentKeyMaterialId = &materialId
		k.PendingKey = nil
	} else {
		// We create a new one
		_ = k.ApplyNewKeyMaterial()
	}

	k.ManualKeyRotations++
	return nil
}

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
