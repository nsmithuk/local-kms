package cmk

//------------------------------------------

type KeyType int
const (
	TypeAes 		KeyType = iota
	TypeRsa
	TypeEcc
)

//---

type CustomerMasterKeySpec string
const (
	SpecSymmetricDefault 	 	CustomerMasterKeySpec = "SYMMETRIC_DEFAULT"
	SpecEccNistP256				CustomerMasterKeySpec = "ECC_NIST_P256"
	SpecEccNistP384				CustomerMasterKeySpec = "ECC_NIST_P384"
	SpecEccNistP521				CustomerMasterKeySpec = "ECC_NIST_P521"
)

func IsValidSpec(t string) bool {
	needle := CustomerMasterKeySpec(t)
	haystack := []CustomerMasterKeySpec{SpecSymmetricDefault, SpecEccNistP256, SpecEccNistP384, SpecEccNistP521}

	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}

//---

type EncryptionAlgorithm string
const (
	EncryptionAlgorithmAes		EncryptionAlgorithm = "SYMMETRIC_DEFAULT"
)

//---

type SigningAlgorithm string
const (
	SigningAlgorithmEcdsaSha256		SigningAlgorithm = "ECDSA_SHA_256"
)

//---

type KeyUsage string
const (
	UsageEncryptDecrypt		KeyUsage = "ENCRYPT_DECRYPT"
	UsageSignVerify			KeyUsage = "SIGN_VERIFY"
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
	AWSAccountId string 			`json:",omitempty"`
	Arn string 						`json:",omitempty"`
	CreationDate int64 				`json:",omitempty"`
	DeletionDate int64 				`json:",omitempty"`
	Description *string								  `yaml:"Description"`
	Enabled bool									  `yaml:"Enabled"`
	ExpirationModel string			`json:",omitempty"`
	KeyId string 					`json:",omitempty" yaml:"KeyId"`
	KeyManager string 				`json:",omitempty"`
	KeyState string 				`json:",omitempty"`
	KeyUsage KeyUsage 				`json:",omitempty"`
	Origin string 					`json:",omitempty"`
	ValidTo int64 					`json:",omitempty"`

	SigningAlgorithms []SigningAlgorithm		`json:",omitempty"`
	EncryptionAlgorithms []EncryptionAlgorithm		`json:",omitempty"`
	CustomerMasterKeySpec CustomerMasterKeySpec		`json:",omitempty"`
}
