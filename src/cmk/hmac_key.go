package cmk

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"time"

	"github.com/nsmithuk/local-kms/src/service"
)

type HmacKey struct {
	BaseKey
	BackingKeys         [][]byte
	NextKeyRotation     time.Time
	ParametersForImport ParametersForImport
}

func NewHmacKey(keySpec KeySpec, metadata KeyMetadata, policy string, origin KeyOrigin) (*HmacKey, error) {
	k := &HmacKey{
		BackingKeys: [][]byte{},
	}

	var keySize int
	switch keySpec {
	case SpecHmac224:
		keySize = 28
	case SpecHmac256:
		keySize = 32
	case SpecHmac384:
		keySize = 48
	case SpecHmac512:
		keySize = 64
	default:
		return nil, fmt.Errorf("unsupported HMAC key spec: %s", keySpec)
	}

	if origin != KeyOriginExternal {
		k.BackingKeys = append(k.BackingKeys, service.GenerateRandomData(uint16(keySize)))
	}

	k.Type = TypeHmac
	k.Metadata = metadata
	k.Policy = policy

	//---

	k.Metadata.KeyUsage = UsageGenerateVerifyMac
	k.Metadata.KeySpec = keySpec
	k.Metadata.CustomerMasterKeySpec = keySpec
	k.Metadata.SigningAlgorithms = getHmacSigningAlgorithms(keySpec)

	return k, nil
}

//----------------------------------------------------

func (k *HmacKey) GetArn() string {
	return k.GetMetadata().Arn
}

func (k *HmacKey) GetPolicy() string {
	return k.Policy
}

func (k *HmacKey) GetKeyType() KeyType {
	return k.Type
}

func (k *HmacKey) GetMetadata() *KeyMetadata {
	return &k.Metadata
}

//----------------------------------------------------

func (k *HmacKey) GetParametersForImport() *ParametersForImport {
	return &k.ParametersForImport
}

func (k *HmacKey) SetParametersForImport(p *ParametersForImport) {
	k.ParametersForImport = *p
}

func (k *HmacKey) ImportKeyMaterial(m []byte) error {
	expectedSize := getHmacKeySize(k.Metadata.KeySpec)
	if len(m) != expectedSize {
		return fmt.Errorf("Invalid key length. Key must be %d bytes in length", expectedSize)
	}

	// If this is the first time we're importing key material then we're all good
	if len(k.BackingKeys) == 0 {
		k.BackingKeys = append(k.BackingKeys, m)
	} else {
		// Check if the key material matches what was already imported
		existing := k.BackingKeys[0]
		if len(existing) != len(m) {
			return errors.New("Key material does not match existing key material")
		}
		for i, b := range m {
			if existing[i] != b {
				return errors.New("Key material does not match existing key material")
			}
		}
	}

	return nil
}

func (k *HmacKey) RotateIfNeeded() bool {
	if !k.NextKeyRotation.IsZero() && k.NextKeyRotation.Before(time.Now()) {
		keySize := getHmacKeySize(k.Metadata.KeySpec)
		k.BackingKeys = append(k.BackingKeys, service.GenerateRandomData(uint16(keySize)))

		// Reset the rotation timer
		k.NextKeyRotation = time.Now().AddDate(1, 0, 0)

		// The key did rotate
		return true
	}

	// The key did not rotate
	return false
}

//----------------------------------------------------

func (k *HmacKey) GenerateMac(message []byte, algorithm SigningAlgorithm) ([]byte, error) {
	if len(k.BackingKeys) == 0 {
		return nil, errors.New("no backing keys available")
	}

	hasher, err := getHashFunction(algorithm)
	if err != nil {
		return nil, err
	}

	// Use the most recent backing key (index 0)
	h := hmac.New(hasher, k.BackingKeys[0])
	h.Write(message)
	return h.Sum(nil), nil
}

func (k *HmacKey) VerifyMac(message []byte, mac []byte, algorithm SigningAlgorithm) (bool, error) {
	if len(k.BackingKeys) == 0 {
		return false, errors.New("no backing keys available")
	}

	hasher, err := getHashFunction(algorithm)
	if err != nil {
		return false, err
	}

	// Try verification against all backing keys (for key rotation support)
	for _, key := range k.BackingKeys {
		h := hmac.New(hasher, key)
		h.Write(message)
		expectedMac := h.Sum(nil)

		if hmac.Equal(mac, expectedMac) {
			return true, nil
		}
	}

	return false, nil
}

//----------------------------------------------------
// Helper functions

func getHmacKeySize(keySpec KeySpec) int {
	switch keySpec {
	case SpecHmac224:
		return 28
	case SpecHmac256:
		return 32
	case SpecHmac384:
		return 48
	case SpecHmac512:
		return 64
	default:
		return 32 // Default to 256-bit
	}
}

func getHashFunction(algorithm SigningAlgorithm) (func() hash.Hash, error) {
	switch algorithm {
	case SigningAlgorithmHmacSha224:
		return sha256.New224, nil
	case SigningAlgorithmHmacSha256:
		return sha256.New, nil
	case SigningAlgorithmHmacSha384:
		return sha512.New384, nil
	case SigningAlgorithmHmacSha512:
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("unsupported HMAC algorithm: %s", algorithm)
	}
}

func getHmacSigningAlgorithms(keySpec KeySpec) []SigningAlgorithm {
	switch keySpec {
	case SpecHmac224:
		return []SigningAlgorithm{SigningAlgorithmHmacSha224}
	case SpecHmac256:
		return []SigningAlgorithm{SigningAlgorithmHmacSha256}
	case SpecHmac384:
		return []SigningAlgorithm{SigningAlgorithmHmacSha384}
	case SpecHmac512:
		return []SigningAlgorithm{SigningAlgorithmHmacSha512}
	default:
		return []SigningAlgorithm{SigningAlgorithmHmacSha256}
	}
}

//----------------------------------------------------
// Construct key from YAML (seeding)

func (k *HmacKey) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type YamlKey struct {
		Metadata        KeyMetadata `yaml:"Metadata"`
		BackingKeys     []string    `yaml:"BackingKeys"`
		NextKeyRotation time.Time   `yaml:"NextKeyRotation"`
	}

	yk := YamlKey{}
	if err := unmarshal(&yk); err != nil {
		return &UnmarshalYAMLError{err.Error()}
	}

	k.Type = TypeHmac
	k.Metadata = yk.Metadata
	defaultSeededKeyMetadata(&k.Metadata)
	k.NextKeyRotation = yk.NextKeyRotation

	//-------------------------
	// Decode backing keys

	if k.Metadata.Origin == KeyOriginExternal {
		switch {
		case len(yk.BackingKeys) == 0:
			return nil
		case len(yk.BackingKeys) > 1:
			return &UnmarshalYAMLError{"EXTERNAL keys can only have a single backing key"}
		}
	}

	if len(yk.BackingKeys) < 1 {
		return &UnmarshalYAMLError{"At least one backing key must be supplied"}
	}

	keySpec := yk.Metadata.KeySpec
	expectedKeySize := getHmacKeySize(keySpec)
	k.BackingKeys = make([][]byte, len(yk.BackingKeys))

	for i, keyStr := range yk.BackingKeys {
		keyBytes, err := hex.DecodeString(keyStr)
		if err != nil {
			return &UnmarshalYAMLError{fmt.Sprintf("Unable to decode hex key: %s", err)}
		}

		if len(keyBytes) != expectedKeySize {
			return &UnmarshalYAMLError{
				fmt.Sprintf(
					"Backing key must be hex encoded and exactly %d bytes. %d bytes found",
					expectedKeySize, len(keyBytes)),
			}
		}

		k.BackingKeys[i] = keyBytes
	}

	k.Metadata.KeyUsage = UsageGenerateVerifyMac

	if k.Metadata.Origin == KeyOriginExternal && len(k.BackingKeys) == 0 {
		k.Metadata.KeyState = KeyStatePendingImport
		k.Metadata.Enabled = false
	}

	k.Metadata.CustomerMasterKeySpec = keySpec
	k.Metadata.SigningAlgorithms = getHmacSigningAlgorithms(keySpec)

	return nil
}
