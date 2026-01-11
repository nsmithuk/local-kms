package kms

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/nsmithuk/local-kms/internal/kms/cmk"
	"github.com/nsmithuk/local-kms/internal/kms/data"
	"github.com/nsmithuk/local-kms/internal/kms/kmserr"
	"github.com/nsmithuk/local-kms/internal/kms/validation"
)

func (k KmsService) DeriveSharedSecret(ctx context.Context, req awskms.DeriveSharedSecretInput) (*awskms.DeriveSharedSecretOutput, []error) {
	validator := validation.Validator{}
	validationErrors := make([]error, 0)

	keyId, err := k.ResolveKeyArn(req.KeyId)
	if err != nil {
		validationErrors = append(validationErrors, err)
	}

	if err = validator.RequiredPointer(req.PublicKey, "PublicKey"); err != nil {
		validationErrors = append(validationErrors, err)
	}

	if err = validator.RequiredString(string(req.KeyAgreementAlgorithm), "KeyAgreementAlgorithm"); err != nil {
		validationErrors = append(validationErrors, err)
	}

	if req.Recipient != nil {
		validationErrors = append(validationErrors, fmt.Errorf("recipient is not yet supported in local kms"))
	}

	if len(validationErrors) > 0 {
		return nil, validationErrors
	}

	// ---

	key, err := k.Db.LoadKey(keyId)
	if err != nil {
		if errors.Is(err, data.ErrKeyNotFound) {
			return nil, []error{
				kmserr.NewValidation(kmserr.CauseNotFoundException, "A key with the arn %s does not exists", keyId),
			}
		}
		return nil, []error{err}
	}

	//---

	metadata := key.GetMetadata()

	sharedSecret, err := key.DeriveSharedSecret(req.PublicKey, req.KeyAgreementAlgorithm)
	if err != nil {
		if errors.Is(err, cmk.ErrOperationNotSupported) {
			return nil, []error{
				kmserr.NewValidation(kmserr.CauseUnsupportedOperationException, "DeriveSharedSecret not supported with KeySpec %s", metadata.KeySpec),
			}
		}
		return nil, []error{err}
	}

	//---

	slog.Info("DeriveSharedSecret Success",
		"KeyId", *metadata.KeyId,
		"KeySpec", metadata.KeySpec,
		"KeyUsage", metadata.KeyUsage,
		"KeyAgreementAlgorithm", req.KeyAgreementAlgorithm,
		"SharedSecret", sharedSecret,
	)

	//---

	return &awskms.DeriveSharedSecretOutput{
		KeyId:                 &keyId,
		KeyAgreementAlgorithm: req.KeyAgreementAlgorithm,
		KeyOrigin:             metadata.Origin,
		SharedSecret:          sharedSecret,
	}, nil
}
