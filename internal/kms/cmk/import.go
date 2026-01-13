package cmk

import (
	"crypto/rsa"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type ParametersForImport struct {
	ParametersValidTo time.Time
	ImportToken       []byte
	PrivateKey        rsa.PrivateKey
	WrappingAlgorithm types.AlgorithmSpec
}
