package cmk

//------------------------------------------

type KeyType int

const (
	TypeAes 		KeyType = iota
	TypeRsa
	TypeEcc
)

//------------------------------------------

type Key interface {
	GetArn() string
	GetPolicy() string
	GetKeyType() KeyType
	GetMetadata() *KeyMetadata
}

//------------------------------------------

type BaseKey struct {
	Type			KeyType
	Metadata 		KeyMetadata
	Policy 			string
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
	ValidTo int64 			`json:",omitempty"`
}
