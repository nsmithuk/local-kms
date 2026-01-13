package cmk

import (
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

var ErrOperationNotSupported = errors.New("operation not supported")

type Key interface {
	GetArn() string
	//GetPolicy() string
	GetKeyType() KeyType
	GetMetadata() *types.KeyMetadata
	IsPendingDeletion() bool
	ShouldBeDeleted() bool
	ApplyNewKeyMaterial() error
	ApplySeedingKeyMaterial(material SeedingKeyMaterial) error

	// Operation specific functions
	GetPublicKey() ([]byte, error)

	Sign([]byte, types.SigningAlgorithmSpec, types.MessageType) ([]byte, error)
	Verify([]byte, types.SigningAlgorithmSpec, types.MessageType, []byte) (bool, error)

	GenerateMac([]byte, types.MacAlgorithmSpec) ([]byte, error)
	VerifyMac([]byte, types.MacAlgorithmSpec, []byte) (bool, error)

	DeriveSharedSecret([]byte, types.KeyAgreementAlgorithmSpec) ([]byte, error)

	Encrypt([]byte, types.EncryptionAlgorithmSpec, map[string]string) ([]byte, error)
	Decrypt([]byte, types.EncryptionAlgorithmSpec, map[string]string) ([]byte, error)
}

type KeyType string

const (
	TypeEcdsaKey     KeyType = "ecdsa"
	TypeEd25519Key   KeyType = "ed25519"
	TypeHmacKey      KeyType = "hmac"
	TypeMlDsaKey     KeyType = "ml-dsa"
	TypeRsaKey       KeyType = "rsa"
	TypeSymmetricKey KeyType = "symmetric"
)

func GetKeyType(k KeyType) (Key, error) {
	switch k {
	case TypeEcdsaKey:
		return &EcdsaKey{}, nil
	case TypeEd25519Key:
		return &Ed25519Key{}, nil
	case TypeHmacKey:
		return &HmacKey{}, nil
	case TypeMlDsaKey:
		return &MlDsaKey{}, nil
	case TypeRsaKey:
		return &RsaKey{}, nil
	case TypeSymmetricKey:
		return &SymmetricKey{}, nil
	}
	return nil, fmt.Errorf("unsupported key type: %s", k)
}

type BaseKey struct {
	KeyType  KeyType
	Metadata types.KeyMetadata
	Policy   string
}

func (b *BaseKey) GetArn() string {
	if b.Metadata.Arn == nil {
		return ""
	}
	return *b.Metadata.Arn
}

func (b *BaseKey) GetMetadata() *types.KeyMetadata {
	b.Metadata.CustomerMasterKeySpec = types.CustomerMasterKeySpec(b.Metadata.KeySpec)
	return &b.Metadata
}

func (b *BaseKey) IsPendingDeletion() bool {
	return b.GetMetadata().DeletionDate != nil
}

func (b *BaseKey) ShouldBeDeleted() bool {
	deletionDate := b.GetMetadata().DeletionDate
	return deletionDate != nil && time.Now().After(*deletionDate)
}

func (b *BaseKey) GetKeyType() KeyType {
	return b.KeyType
}

//---------------------------------------------

func (b *BaseKey) enforceKeyUsageType(v types.KeyUsageType) error {
	if b.Metadata.KeyUsage != v {
		return fmt.Errorf("unsupported KeyUsageType: %v. Expected %s", v, b.Metadata.KeyUsage)
	}
	return nil
}

//func (b *BaseKey) enforceMacAlgorithmSpec(v types.MacAlgorithmSpec) error {
//	if b.Metadata.MacAlgorithms == nil {
//		return fmt.Errorf("key does not support Mac Algorithms")
//	}
//	if !slices.Contains(b.Metadata.MacAlgorithms, v) {
//		return fmt.Errorf("unsupported MacAlgorithm: %s. Expected %v", v, b.Metadata.MacAlgorithms)
//	}
//	return nil
//}
//
//func (b *BaseKey) enforceSigningAlgorithmSpec(v types.SigningAlgorithmSpec) error {
//	if b.Metadata.MacAlgorithms == nil {
//		return fmt.Errorf("key does not support Mac Algorithms")
//	}
//	if !slices.Contains(b.Metadata.SigningAlgorithms, v) {
//		return fmt.Errorf("unsupported SigningAlgorithmSpec: %s. Expected %v", v, b.Metadata.SigningAlgorithms)
//	}
//	return nil
//}

//---------------------------------------------
// Base Operation functions
// We override these at the key type level, if the operation is supported.

func (b *BaseKey) GetPublicKey() ([]byte, error) {
	return nil, ErrOperationNotSupported
}

func (b *BaseKey) Sign([]byte, types.SigningAlgorithmSpec, types.MessageType) ([]byte, error) {
	return nil, ErrOperationNotSupported
}

func (b *BaseKey) Verify([]byte, types.SigningAlgorithmSpec, types.MessageType, []byte) (bool, error) {
	return false, ErrOperationNotSupported
}

func (b *BaseKey) GenerateMac([]byte, types.MacAlgorithmSpec) ([]byte, error) {
	return nil, ErrOperationNotSupported
}

func (b *BaseKey) VerifyMac([]byte, types.MacAlgorithmSpec, []byte) (bool, error) {
	return false, ErrOperationNotSupported
}

func (b *BaseKey) DeriveSharedSecret([]byte, types.KeyAgreementAlgorithmSpec) ([]byte, error) {
	return nil, ErrOperationNotSupported
}

func (b *BaseKey) Encrypt([]byte, types.EncryptionAlgorithmSpec, map[string]string) ([]byte, error) {
	return nil, ErrOperationNotSupported
}

func (b *BaseKey) Decrypt([]byte, types.EncryptionAlgorithmSpec, map[string]string) ([]byte, error) {
	return nil, ErrOperationNotSupported
}
