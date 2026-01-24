package kms

import (
	"context"
	"errors"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/nsmithuk/local-kms/internal/kms/data"
	"github.com/nsmithuk/local-kms/internal/kms/kmserr"
	"github.com/nsmithuk/local-kms/internal/kms/validation"
)

func (k KmsService) TagResource(ctx context.Context, req awskms.TagResourceInput) (*awskms.TagResourceOutput, []error) {
	validator := validation.Validator{}
	validationErrors := make([]error, 0)

	if errs := validator.Tags(req.Tags); len(errs) > 0 {
		validationErrors = append(validationErrors, errs...)
	}

	if len(validationErrors) > 0 {
		return nil, validationErrors
	}

	keyId, err := k.ResolveKeyArn(req.KeyId)
	if err != nil {
		return nil, []error{err}
	}

	key, err := k.Db.LoadKey(keyId)
	if err != nil {
		if errors.Is(err, data.ErrKeyNotFound) {
			return nil, []error{
				kmserr.NewValidation(kmserr.CauseNotFoundException, "A key with the arn %s does not exists", keyId),
			}
		}
		return nil, []error{err}
	}

	if key.IsPendingDeletion() {
		return nil, []error{
			kmserr.NewValidation(kmserr.CauseKMSInvalidStateException, "%s is pending deletion.", key.GetArn()),
		}
	}

	for _, tag := range req.Tags {
		if err := k.Db.SaveTag(key, tag); err != nil {
			return nil, []error{err}
		}
	}

	return &awskms.TagResourceOutput{}, nil
}
