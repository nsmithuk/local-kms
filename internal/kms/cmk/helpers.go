package cmk

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"io"
	"math"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"golang.org/x/exp/constraints"
)

func GenerateRandomData[T constraints.Integer](size T) []byte {
	if size < 0 {
		panic("size must be non-negative")
	}

	if uint64(size) > math.MaxInt {
		panic("size overflows int")
	}

	data := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		panic(err)
	}
	return data
}

func hashMessage(message []byte, algorithm types.SigningAlgorithmSpec) ([]byte, error) {
	var digest hash.Hash

	switch algorithm {
	case types.SigningAlgorithmSpecEcdsaSha256, types.SigningAlgorithmSpecRsassaPkcs1V15Sha256, types.SigningAlgorithmSpecRsassaPssSha256:
		digest = sha256.New()
	case types.SigningAlgorithmSpecEcdsaSha384, types.SigningAlgorithmSpecRsassaPkcs1V15Sha384, types.SigningAlgorithmSpecRsassaPssSha384:
		digest = sha512.New384()
	case types.SigningAlgorithmSpecEcdsaSha512, types.SigningAlgorithmSpecRsassaPkcs1V15Sha512, types.SigningAlgorithmSpecRsassaPssSha512:
		digest = sha512.New()
	default:
		return nil, fmt.Errorf("unsupported signing algorithm %v", algorithm)
	}

	digest.Write(message)
	return digest.Sum(nil), nil
}
