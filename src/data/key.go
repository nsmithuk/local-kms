package data

import "time"

type Key struct {
	Metadata 		KeyMetadata
	BackingKeys		[][32]byte
	NextKeyRotation	time.Time
}

type KeyMetadata struct {
	AWSAccountId string `json:",omitempty"`
	Arn string `json:",omitempty"`
	CreationDate int64 `json:",omitempty"`
	DeletionDate int64 `json:",omitempty"`
	Description *string	`json:",omitempty"`
	Enabled bool
	ExpirationModel string `json:",omitempty"`
	KeyId string `json:",omitempty"`
	KeyManager string `json:",omitempty"`
	KeyState string `json:",omitempty"`
	KeyUsage string `json:",omitempty"`
	Origin string `json:",omitempty"`
	ValidTo int64 `json:",omitempty"`
}
