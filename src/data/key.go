package data

import (
	"time"
	"encoding/hex"
	"fmt"
)

type Key struct {
	Metadata 		KeyMetadata
	BackingKeys		[][32]byte
	NextKeyRotation	time.Time
}

type KeyMetadata struct {
	AWSAccountId string 	`json:",omitempty"`
	Arn string 				`json:",omitempty"`
	CreationDate int64 		`json:",omitempty"`
	DeletionDate int64 		`json:",omitempty"`
	Description *string						  `yaml:"Description"`
	Enabled bool							  `yaml:"Enabled"`
	ExpirationModel string	`json:",omitempty"`
	KeyId string 			`json:",omitempty" yaml:"KeyId"`
	KeyManager string 		`json:",omitempty"`
	KeyState string 		`json:",omitempty"`
	KeyUsage string 		`json:",omitempty"`
	Origin string 			`json:",omitempty"`
	Policy string 			`json:",omitempty"`
	ValidTo int64 			`json:",omitempty"`
}

//----------------------------------------------------
// Construct key from YAML

type UnmarshalYAMLError struct {
	message string
}

func (e *UnmarshalYAMLError) Error() string {
	return fmt.Sprintf("Error unmarshaling YAML: %s", e.message)
}

//---

func (k *Key) UnmarshalYAML(unmarshal func(interface{}) error) error {

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
