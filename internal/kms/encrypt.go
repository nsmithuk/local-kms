package kms

import (
	"context"
	"errors"
	"log/slog"
	"slices"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/nsmithuk/local-kms/internal/kms/cmk"
	"github.com/nsmithuk/local-kms/internal/kms/kmserr"
	"github.com/nsmithuk/local-kms/internal/kms/validation"
)

func (k KmsService) Encrypt(ctx context.Context, req awskms.EncryptInput) (*awskms.EncryptOutput, []error) {

	key, err := k.getUsableKey(req.KeyId)
	if err != nil {
		return nil, []error{err}
	}

	validator := validation.Validator{}
	validationErrors := make([]error, 0)

	if err = validator.RequiredPointer(req.Plaintext, "Plaintext"); err != nil {
		validationErrors = append(validationErrors, err)
	} else if err = validator.ByteLength(req.Plaintext, "Plaintext", 4096); err != nil {
		validationErrors = append(validationErrors, err)
	}

	if len(validationErrors) > 0 {
		return nil, validationErrors
	}

	keyId := key.GetArn()

	metadata := key.GetMetadata()

	//---

	if key.GetMetadata().KeySpec == types.KeySpecSymmetricDefault && req.EncryptionAlgorithm == "" {
		req.EncryptionAlgorithm = types.EncryptionAlgorithmSpecSymmetricDefault
	}

	if err = validator.RequiredString(string(req.EncryptionAlgorithm), "EncryptionAlgorithm"); err != nil {
		validationErrors = append(validationErrors, err)
	}

	if metadata.EncryptionAlgorithms == nil || !slices.Contains(metadata.EncryptionAlgorithms, req.EncryptionAlgorithm) {
		return nil, []error{
			kmserr.NewValidation(kmserr.CauseValidationError, "encryption algorithm %s is not supported for this key type", req.EncryptionAlgorithm),
		}
	}

	//---

	if key.GetMetadata().KeySpec != types.KeySpecSymmetricDefault && req.EncryptionContext != nil {
		return nil, []error{
			kmserr.NewValidation(kmserr.CauseValidationError, "encryption context is not supported for this key type", req.EncryptionContext),
		}
	}

	//---

	ciphertextBlob, err := key.Encrypt(req.Plaintext, req.EncryptionAlgorithm, req.EncryptionContext)
	if err != nil {
		if errors.Is(err, cmk.ErrOperationNotSupported) {
			return nil, []error{
				kmserr.NewValidation(kmserr.CauseUnsupportedOperationException, "Encrypt not supported with KeySpec %s", metadata.KeySpec),
			}
		}
		return nil, []error{err}
	}

	//---

	slog.Info("Encrypt Success",
		"KeyId", keyId,
		"KeySpec", metadata.KeySpec,
		"KeyUsage", metadata.KeyUsage,
		"EncryptionAlgorithm", req.EncryptionAlgorithm,
		"CiphertextBlob", ciphertextBlob,
	)

	//---

	return &awskms.EncryptOutput{
		KeyId:               &keyId,
		EncryptionAlgorithm: req.EncryptionAlgorithm,
		CiphertextBlob:      ciphertextBlob,
	}, nil
}
