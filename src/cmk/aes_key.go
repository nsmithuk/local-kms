package cmk

import (
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/nsmithuk/local-kms/src/service"
)

type AesKey struct {
	BaseKey
	BackingKeys         [][32]byte
	NextKeyRotation     time.Time
	ParametersForImport ParametersForImport
}

func NewAesKey(metadata KeyMetadata, policy string, origin KeyOrigin) *AesKey {
	k := &AesKey{
		BackingKeys: [][32]byte{},
	}

	if origin != KeyOriginExternal {
		k.BackingKeys = append(k.BackingKeys, generateKey())
	}

	k.Type = TypeAes
	k.Metadata = metadata
	k.Policy = policy

	//---

	k.Metadata.KeyUsage = UsageEncryptDecrypt
	k.Metadata.KeySpec = SpecSymmetricDefault
	k.Metadata.CustomerMasterKeySpec = SpecSymmetricDefault
	k.Metadata.EncryptionAlgorithms = []EncryptionAlgorithm{EncryptionAlgorithmAes}

	return k
}

//----------------------------------------------------

func (k *AesKey) GetArn() string {
	return k.GetMetadata().Arn
}

func (k *AesKey) GetPolicy() string {
	return k.Policy
}

func (k *AesKey) GetKeyType() KeyType {
	return k.Type
}

func (k *AesKey) GetMetadata() *KeyMetadata {
	return &k.Metadata
}

//----------------------------------------------------

func (k *AesKey) GetParametersForImport() *ParametersForImport {
	return &k.ParametersForImport
}

func (k *AesKey) SetParametersForImport(p *ParametersForImport) {
	k.ParametersForImport = *p
}

func (k *AesKey) ImportKeyMaterial(m []byte) error {
	if len(m) != 32 {
		return errors.New("Invalid key length. Key must be 32 bytes in length.")
	}

	var key [32]byte
	copy(key[:], m[:32])

	// If this is the first time we're importing key material then we're all good
	if len(k.BackingKeys) == 0 {
		k.BackingKeys = append(k.BackingKeys, key)

	} else if key != k.BackingKeys[0] {
		// else if the key material doesn't match what was already imported then
		// throw and error
		return errors.New("Key material does not match existing key material.")
	}

	return nil
}

func (k *AesKey) RotateIfNeeded() bool {

	if !k.NextKeyRotation.IsZero() && k.NextKeyRotation.Before(time.Now()) {

		k.BackingKeys = append(k.BackingKeys, generateKey())

		// Reset the rotation timer
		k.NextKeyRotation = time.Now().AddDate(1, 0, 0)

		// The key did rotate
		return true
	}

	// The key did not rotate
	return false
}

//-----------------------

/*
	Generates a new 32 bytes key from random data
*/
func generateKey() [32]byte {
	var key [32]byte
	copy(key[:], service.GenerateRandomData(32))
	return key
}

//----------------------------------------------------
// Construct key from YAML (seeing)

//---

func (k *AesKey) UnmarshalYAML(unmarshal func(interface{}) error) error {

	// Cannot use embedded 'Key' struct
	// https://github.com/go-yaml/yaml/issues/263
	type YamlKey struct {
		Metadata        KeyMetadata `yaml:"Metadata"`
		BackingKeys     []string    `yaml:"BackingKeys"`
		NextKeyRotation time.Time   `yaml:"NextKeyRotation"`
	}

	yk := YamlKey{}
	if err := unmarshal(&yk); err != nil {
		return &UnmarshalYAMLError{err.Error()}
	}

	k.Type = TypeAes
	k.Metadata = yk.Metadata
	defaultSeededKeyMetadata(&k.Metadata)
	k.NextKeyRotation = yk.NextKeyRotation

	//-------------------------
	// Decode backing keys

	if k.Metadata.Origin == KeyOriginExternal {
		switch {
		case len(yk.BackingKeys) == 0:
			return nil
		case len(yk.BackingKeys) > 1:
			return &UnmarshalYAMLError{"EXTERNAL keys can only have a single backing key"}
		}
	}

	if len(yk.BackingKeys) < 1 {
		return &UnmarshalYAMLError{"At least one backing key must be supplied"}
	}

	k.BackingKeys = make([][32]byte, len(yk.BackingKeys))

	for i, keyStr := range yk.BackingKeys {

		keyBytes, err := hex.DecodeString(keyStr)
		if err != nil {
			return &UnmarshalYAMLError{fmt.Sprintf("Unable to decode hex key: %s", err)}
		}

		if len(keyBytes) != 32 {
			return &UnmarshalYAMLError{
				fmt.Sprintf(
					"Backing key must be hex encoded and exactly 32 bytes (256 bit). %d bytes found",
					len(keyBytes)),
			}
		}

		copy(k.BackingKeys[i][:], keyBytes[:])
	}
	k.Metadata.KeyUsage = UsageEncryptDecrypt

	if k.Metadata.Origin == KeyOriginExternal && len(k.BackingKeys) == 0 {
		k.Metadata.KeyState = KeyStatePendingImport
		k.Metadata.Enabled = false
	}

	k.Metadata.KeySpec = SpecSymmetricDefault
	k.Metadata.CustomerMasterKeySpec = SpecSymmetricDefault
	k.Metadata.EncryptionAlgorithms = []EncryptionAlgorithm{EncryptionAlgorithmAes}

	return nil
}
