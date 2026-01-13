package kms

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/nsmithuk/local-kms/internal/kms/cmk"
	"github.com/nsmithuk/local-kms/internal/kms/validation"
)

func (k KmsService) GetParametersForImport(ctx context.Context, req awskms.GetParametersForImportInput) (*awskms.GetParametersForImportOutput, []error) {

	key, err := k.getKeyWithState(req.KeyId, types.KeyStatePendingImport)
	if err != nil {
		return nil, []error{err}
	}

	if err := validation.ValidOption(req.WrappingKeySpec, "WrappingKeySpec"); err != nil {
		return nil, []error{err}
	}

	if err := validation.ValidOption(req.WrappingAlgorithm, "WrappingAlgorithm"); err != nil {
		return nil, []error{err}
	}

	switch req.WrappingAlgorithm {
	case types.AlgorithmSpecSm2pke, types.AlgorithmSpecRsaesPkcs1V15:
		return nil, []error{fmt.Errorf("unsupported algorithm: %s", req.WrappingAlgorithm)}
	}

	if req.WrappingKeySpec == types.WrappingKeySpecSm2 {
		return nil, []error{fmt.Errorf("unsupported algorithm: %s", req.WrappingAlgorithm)}
	}

	//---

	metadata := key.GetMetadata()

	// You cannot use the RSAES_OAEP_SHA_* wrapping algorithms with the RSA_2048 wrapping key spec to wrap ECC_NIST_P521 key material.
	if metadata.KeySpec == types.KeySpecEccNistP521 && req.WrappingKeySpec == types.WrappingKeySpecRsa2048 {
		if !(req.WrappingAlgorithm == types.AlgorithmSpecRsaAesKeyWrapSha1 || req.WrappingAlgorithm == types.AlgorithmSpecRsaAesKeyWrapSha256) {
			return nil, []error{fmt.Errorf("unsupported algorithm: %s", req.WrappingAlgorithm)}
		}
	}

	//---

	var bits int
	switch req.WrappingKeySpec {
	case types.WrappingKeySpecRsa2048:
		bits = 2048
	case types.WrappingKeySpecRsa3072:
		bits = 3072
	case types.WrappingKeySpecRsa4096:
		bits = 4096
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, []error{err}
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		return nil, []error{err}
	}

	params := &cmk.ParametersForImport{
		ImportToken:       cmk.GenerateRandomData(2048 / 8),
		ParametersValidTo: time.Now().Add(24 * time.Duration(time.Hour)),
		PrivateKey:        *rsaKey,
		WrappingAlgorithm: req.WrappingAlgorithm,
	}

	key.SetParametersForImport(params)

	//---

	err = k.Db.SaveKey(key)
	if err != nil {
		return nil, []error{err}
	}

	//---

	return &awskms.GetParametersForImportOutput{
		KeyId:             aws.String(key.GetId()),
		ImportToken:       params.ImportToken,
		PublicKey:         pubKeyBytes,
		ParametersValidTo: &params.ParametersValidTo,
	}, nil
}
