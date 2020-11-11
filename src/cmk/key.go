package cmk

//------------------------------------------

type KeyType int

const (
	TypeAes KeyType = iota
	TypeRsa
	TypeEcc
)

//---

type CustomerMasterKeySpec string

const (
	SpecSymmetricDefault CustomerMasterKeySpec = "SYMMETRIC_DEFAULT"
	SpecEccNistP256      CustomerMasterKeySpec = "ECC_NIST_P256"
	SpecEccNistP384      CustomerMasterKeySpec = "ECC_NIST_P384"
	SpecEccNistP521      CustomerMasterKeySpec = "ECC_NIST_P521"
	SpecRsa2048          CustomerMasterKeySpec = "RSA_2048"
	SpecRsa3072          CustomerMasterKeySpec = "RSA_3072"
	SpecRsa4096          CustomerMasterKeySpec = "RSA_4096"
)

//---

type EncryptionAlgorithm string

const (
	EncryptionAlgorithmAes EncryptionAlgorithm = "SYMMETRIC_DEFAULT"
)

//---

type SigningAlgorithm string

const (
	SigningAlgorithmEcdsaSha256   SigningAlgorithm = "ECDSA_SHA_256"
	SigningAlgorithmEcdsaSha384   SigningAlgorithm = "ECDSA_SHA_384"
	SigningAlgorithmEcdsaSha512   SigningAlgorithm = "ECDSA_SHA_512"
	SigningAlgorithmRsaPssSha256  SigningAlgorithm = "RSASSA_PSS_SHA_256"
	SigningAlgorithmRsaPssSha384  SigningAlgorithm = "RSASSA_PSS_SHA_384"
	SigningAlgorithmRsaPssSha512  SigningAlgorithm = "RSASSA_PSS_SHA_512"
	SigningAlgorithmRsaPkcsSha256 SigningAlgorithm = "RSASSA_PKCS1_V1_5_SHA_256"
	SigningAlgorithmRsaPkcsSha384 SigningAlgorithm = "RSASSA_PKCS1_V1_5_SHA_384"
	SigningAlgorithmRsaPkcsSha512 SigningAlgorithm = "RSASSA_PKCS1_V1_5_SHA_512"
)

//---

type KeyUsage string

const (
	UsageEncryptDecrypt KeyUsage = "ENCRYPT_DECRYPT"
	UsageSignVerify     KeyUsage = "SIGN_VERIFY"
)

//------------------------------------------

type Key interface {
	GetArn() string
	GetPolicy() string
	GetKeyType() KeyType
	GetMetadata() *KeyMetadata
}

type SigningKey interface {
	Key
	Sign(digest []byte, algorithm SigningAlgorithm) ([]byte, error)
	HashAndSign(message []byte, algorithm SigningAlgorithm) ([]byte, error)
	Verify(signature []byte, digest []byte, algorithm SigningAlgorithm) (bool, error)
	HashAndVerify(signature []byte, digest []byte, algorithm SigningAlgorithm) (bool, error)
}

//------------------------------------------

type BaseKey struct {
	Type     KeyType
	Metadata KeyMetadata
	Policy   string
}

type KeyMetadata struct {
	AWSAccountId    string   `json:",omitempty"`
	Arn             string   `json:",omitempty"`
	CreationDate    int64    `json:",omitempty"`
	DeletionDate    int64    `json:",omitempty"`
	Description     *string  `yaml:"Description"`
	Enabled         bool     `yaml:"Enabled"`
	ExpirationModel string   `json:",omitempty"`
	KeyId           string   `json:",omitempty" yaml:"KeyId"`
	KeyManager      string   `json:",omitempty"`
	KeyState        string   `json:",omitempty"`
	KeyUsage        KeyUsage `json:",omitempty"`
	Origin          string   `json:",omitempty"`
	ValidTo         int64    `json:",omitempty"`

	SigningAlgorithms     []SigningAlgorithm    `json:",omitempty"`
	EncryptionAlgorithms  []EncryptionAlgorithm `json:",omitempty"`
	CustomerMasterKeySpec CustomerMasterKeySpec `json:",omitempty"`
}
