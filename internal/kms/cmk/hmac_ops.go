package cmk

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

func (k *HmacKey) getHash() (types.MacAlgorithmSpec, hash.Hash, error) {
	switch k.GetMetadata().KeySpec {
	case types.KeySpecHmac224:
		return types.MacAlgorithmSpecHmacSha224, hmac.New(sha256.New224, k.PrivateKey), nil
	case types.KeySpecHmac256:
		return types.MacAlgorithmSpecHmacSha256, hmac.New(sha256.New, k.PrivateKey), nil
	case types.KeySpecHmac384:
		return types.MacAlgorithmSpecHmacSha384, hmac.New(sha512.New384, k.PrivateKey), nil
	case types.KeySpecHmac512:
		return types.MacAlgorithmSpecHmacSha512, hmac.New(sha512.New, k.PrivateKey), nil
	}

	return "", nil, fmt.Errorf("unsupported key spec: %s", k.GetMetadata().KeySpec)
}

func (k *HmacKey) GenerateMac(message []byte, algorithm types.MacAlgorithmSpec) ([]byte, error) {
	expectedAlgorithm, mac, err := k.getHash()
	if err != nil {
		return nil, err
	}

	if algorithm != expectedAlgorithm {
		return nil, fmt.Errorf("invalid key algorithm '%s' for key spec %s", algorithm, k.GetMetadata().KeySpec)
	}

	_, err = mac.Write(message)
	return mac.Sum(nil), err
}

func (k *HmacKey) VerifyMac(message []byte, algorithm types.MacAlgorithmSpec, macProvided []byte) (bool, error) {
	expectedAlgorithm, mac, err := k.getHash()
	if err != nil {
		return false, err
	}

	if algorithm != expectedAlgorithm {
		return false, fmt.Errorf("invalid key algorithm '%s' for key spec %s", algorithm, k.GetMetadata().KeySpec)
	}

	_, err = mac.Write(message)
	if err != nil {
		return false, err
	}

	macCalculated := mac.Sum(nil)
	return hmac.Equal(macProvided, macCalculated), nil
}
