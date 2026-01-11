package kms

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/nsmithuk/local-kms/internal/kms/cmk"
	"github.com/nsmithuk/local-kms/internal/kms/data"
	"github.com/nsmithuk/local-kms/internal/kms/kmserr"
	"github.com/nsmithuk/local-kms/internal/kms/validation"
)

func (k KmsService) Decrypt(ctx context.Context, req awskms.DecryptInput) (*awskms.DecryptOutput, []error) {

	ctb := cmk.CiphertextBlob(req.CiphertextBlob)
	ctbKeyId, err := ctb.KeyArn()
	if err == nil {
		// If there's no error, we found an ARN in the CiphertextBlob Metadata
		if req.KeyId == nil {
			req.KeyId = &ctbKeyId
		}
	}

	//---

	validator := validation.Validator{}
	validationErrors := make([]error, 0)

	keyId, err := k.ResolveKeyArn(req.KeyId)
	if err != nil {
		validationErrors = append(validationErrors, err)
	}

	if len(ctbKeyId) > 0 && ctbKeyId != keyId {
		// If we hve a supplied key, and oen from metadata, they must match.
		return nil, []error{fmt.Errorf("KeyId '%s' does not match the key within the CiphertextBlob metedata", *req.KeyId)}
	}

	if err = validator.RequiredPointer(req.CiphertextBlob, "CiphertextBlob"); err != nil {
		validationErrors = append(validationErrors, err)
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

	plaintext, err := key.Decrypt(req.CiphertextBlob, req.EncryptionAlgorithm, req.EncryptionContext)
	if err != nil {
		if errors.Is(err, cmk.ErrOperationNotSupported) {
			return nil, []error{
				kmserr.NewValidation(kmserr.CauseUnsupportedOperationException, "Encrypt not supported with KeySpec %s", metadata.KeySpec),
			}
		}
		return nil, []error{err}
	}

	//---

	slog.Info("Decrypt Success",
		"KeyId", keyId,
		"KeySpec", metadata.KeySpec,
		"KeyUsage", metadata.KeyUsage,
		"EncryptionAlgorithm", req.EncryptionAlgorithm,
		//"KeyMaterialId", *metadata.CurrentKeyMaterialId, Only works for AES keys
		"Plaintext", plaintext,
	)

	//---

	return &awskms.DecryptOutput{
		KeyId:               &keyId,
		Plaintext:           plaintext,
		EncryptionAlgorithm: req.EncryptionAlgorithm,
		KeyMaterialId:       metadata.CurrentKeyMaterialId,
	}, nil
}
