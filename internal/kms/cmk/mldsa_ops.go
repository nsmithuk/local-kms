package cmk

import (
	"crypto/rand"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/nsmithuk/local-kms/internal/kms/cmk/x509mldsa"
)

//---------------------------------------------
// Operation functions

func (k *MlDsaKey) GetPublicKey() ([]byte, error) {
	key, err := k.PublicKey()
	if err != nil {
		return nil, err
	}

	return x509mldsa.MarshalPKIXPublicKey(key)
}

func (k *MlDsaKey) Sign(message []byte, algorithm types.SigningAlgorithmSpec, messageType types.MessageType) ([]byte, error) {
	if err := k.enforceKeyUsageType(types.KeyUsageTypeSignVerify); err != nil {
		return nil, err
	}

	if algorithm != types.SigningAlgorithmSpecMlDsaShake256 {
		return nil, fmt.Errorf("unsupported signing algorithm: %s", algorithm)
	}

	sk, err := k.PrivateKey()
	if err != nil {
		return nil, err
	}

	switch messageType {
	case types.MessageTypeExternalMu:
		return sk.SignWithExternalMU(rand.Reader, message, nil)
	case types.MessageTypeRaw:
		return sk.Sign(rand.Reader, message, nil)
	default:
		return nil, fmt.Errorf("unsupported message type: %s", messageType)
	}

}

func (k *MlDsaKey) Verify(message []byte, algorithm types.SigningAlgorithmSpec, messageType types.MessageType, signature []byte) (bool, error) {
	if err := k.enforceKeyUsageType(types.KeyUsageTypeSignVerify); err != nil {
		return false, err
	}

	if algorithm != types.SigningAlgorithmSpecMlDsaShake256 {
		return false, fmt.Errorf("unsupported signing algorithm: %s", algorithm)
	}

	sk, err := k.PrivateKey()
	if err != nil {
		return false, err
	}

	switch messageType {
	case types.MessageTypeExternalMu:
		return sk.PublicKey().VerifyWithExternalMU(message, signature), nil
	case types.MessageTypeRaw:
		return sk.PublicKey().Verify(message, signature), nil
	default:
		return false, fmt.Errorf("unsupported message type: %s", messageType)
	}
}
