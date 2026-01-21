package kms

import (
	"encoding/base64"
	"fmt"

	"github.com/nsmithuk/local-kms/internal/kms/cmk"
)

func EncodeMarker(in string) *string {
	nextMarkerB64 := base64.StdEncoding.EncodeToString([]byte(in))
	return &nextMarkerB64
}

func DecodeMarker(in *string) (*string, error) {
	data, err := base64.StdEncoding.DecodeString(*in)
	if err != nil {
		return nil, err
	}
	nextMarketStr := string(data)
	return &nextMarketStr, nil
}

func getKeyPolicy(key cmk.Key) (string, error) {
	if key == nil {
		return "", fmt.Errorf("key is nil")
	}

	switch typedKey := key.(type) {
	case *cmk.SymmetricKey:
		return typedKey.Policy, nil
	case *cmk.RsaKey:
		return typedKey.Policy, nil
	case *cmk.EcdsaKey:
		return typedKey.Policy, nil
	case *cmk.Ed25519Key:
		return typedKey.Policy, nil
	case *cmk.HmacKey:
		return typedKey.Policy, nil
	case *cmk.MlDsaKey:
		return typedKey.Policy, nil
	default:
		return "", fmt.Errorf("unsupported key type for policy")
	}
}

func setKeyPolicy(key cmk.Key, policy string) error {
	if key == nil {
		return fmt.Errorf("key is nil")
	}

	switch typedKey := key.(type) {
	case *cmk.SymmetricKey:
		typedKey.Policy = policy
	case *cmk.RsaKey:
		typedKey.Policy = policy
	case *cmk.EcdsaKey:
		typedKey.Policy = policy
	case *cmk.Ed25519Key:
		typedKey.Policy = policy
	case *cmk.HmacKey:
		typedKey.Policy = policy
	case *cmk.MlDsaKey:
		typedKey.Policy = policy
	default:
		return fmt.Errorf("unsupported key type for policy")
	}

	return nil
}
