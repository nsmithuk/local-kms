package cmk

import (
	"encoding/hex"
	"fmt"
	"github.com/nsmithuk/local-kms/src/service"
	"time"
)

type AesKey struct {
	BaseKey
	BackingKeys		[][32]byte
	NextKeyRotation	time.Time
}

func NewAesKey(metadata KeyMetadata, policy string) *AesKey {
	k := &AesKey{
		BackingKeys: [][32]byte{generateKey()},
	}

	k.Type = TypeAes
	k.Metadata = metadata
	k.Policy = policy

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

func (k *AesKey) RotateIfNeeded() bool {

	if !k.NextKeyRotation.IsZero() && k.NextKeyRotation.Before(time.Now()){

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

type UnmarshalYAMLError struct {
	message string
}

func (e *UnmarshalYAMLError) Error() string {
	return fmt.Sprintf("Error unmarshaling YAML: %s", e.message)
}

//---

func (k *AesKey) UnmarshalYAML(unmarshal func(interface{}) error) error {

	// Cannot use embedded 'Key' struct
	// https://github.com/go-yaml/yaml/issues/263
	type YamlKey struct {
		Metadata 		KeyMetadata		`yaml:"Metadata"`
		BackingKeys		[]string		`yaml:"BackingKeys"`
		NextKeyRotation	time.Time		`yaml:"NextKeyRotation"`
	}

	yk := YamlKey{}
	if err := unmarshal(&yk); err != nil {
		return &UnmarshalYAMLError{ err.Error() }
	}

	k.Type = TypeAes
	k.Metadata = yk.Metadata
	k.NextKeyRotation = yk.NextKeyRotation

	//-------------------------
	// Decode backing keys

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

	return nil
}


