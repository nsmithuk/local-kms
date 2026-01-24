package cmk

import (
	"crypto/sha3"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/nsmithuk/local-kms/internal/kms/kmserr"
	"gopkg.in/yaml.v3"
)

type SymmetricBackingKey struct {
	ParentKeyIdDigest [8]byte
	Material          [32]byte

	//MaterialState types.KeyMaterialState
	//ImportState   types.ImportState
	//RotationDate  *time.Time
	//RotationType  types.RotationType
	//ValidTo       *time.Time
}

func NewSymmetricBackingKey(k *SymmetricKey) SymmetricBackingKey {
	var key [32]byte
	copy(key[:], GenerateRandomData(32))
	return NewSymmetricBackingKeyWithMaterial(k, key)
}

func NewSymmetricBackingKeyWithMaterial(k *SymmetricKey, material [32]byte) SymmetricBackingKey {
	var digest [8]byte
	copy(digest[:], sha3.SumSHAKE256([]byte(k.GetId()), 8))

	return SymmetricBackingKey{
		Material:          material,
		ParentKeyIdDigest: digest,
	}
}

func (bk *SymmetricBackingKey) MaterialId() string {
	m := append(bk.ParentKeyIdDigest[:], bk.Material[:]...)
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
	key := NewSymmetricBackingKey(k)
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
		key := NewSymmetricBackingKeyWithMaterial(k, keyArr)

		materialId := key.MaterialId()
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
	key := NewSymmetricBackingKeyWithMaterial(k, keyArr)

	newMaterialId := key.MaterialId()

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
		materialId := k.PendingKey.MaterialId()

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

func (k *SymmetricKey) ListKeyRotations(types.IncludeKeyMaterial) []types.RotationsListEntry {
	rotations := make([]types.RotationsListEntry, 0, len(k.BackingKeys)+len(k.PreviousBackingKeys))

	for _, key := range k.BackingKeys {
		state := types.KeyMaterialStateNonCurrent
		if k.GetMetadata().CurrentKeyMaterialId != nil && key.MaterialId() == *k.GetMetadata().CurrentKeyMaterialId {
			state = types.KeyMaterialStateCurrent
		}

		rotations = append(rotations, types.RotationsListEntry{
			KeyId:            aws.String(k.GetId()),
			ExpirationModel:  types.ExpirationModelTypeKeyMaterialDoesNotExpire,
			ImportState:      types.ImportStateImported,
			KeyMaterialId:    aws.String(key.MaterialId()),
			KeyMaterialState: state,
		})
	}
	for _, key := range k.PreviousBackingKeys {
		rotations = append(rotations, types.RotationsListEntry{
			KeyId:            aws.String(k.GetId()),
			ExpirationModel:  types.ExpirationModelTypeKeyMaterialDoesNotExpire,
			ImportState:      types.ImportStateImported,
			KeyMaterialId:    aws.String(key.MaterialId()),
			KeyMaterialState: types.KeyMaterialStateNonCurrent,
		})
	}
	if k.PendingKey != nil {
		rotations = append(rotations, types.RotationsListEntry{
			KeyId:            aws.String(k.GetId()),
			ExpirationModel:  types.ExpirationModelTypeKeyMaterialDoesNotExpire,
			ImportState:      types.ImportStatePendingImport,
			KeyMaterialId:    aws.String(k.PendingKey.MaterialId()),
			KeyMaterialState: types.KeyMaterialStatePendingRotation,
		})
	}

	return rotations
}

func (k *SymmetricKey) UnmarshalYAML(value *yaml.Node) error {
	return nil
}
