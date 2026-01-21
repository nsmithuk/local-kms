package kms

import (
	"context"
	"errors"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/nsmithuk/local-kms/internal/kms/cmk"
	"github.com/nsmithuk/local-kms/internal/kms/data"
	"github.com/nsmithuk/local-kms/internal/kms/kmserr"
)

func (k KmsService) GetKeyRotationStatus(ctx context.Context, req awskms.GetKeyRotationStatusInput) (*awskms.GetKeyRotationStatusOutput, []error) {
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

	if key.GetMetadata().KeySpec != types.KeySpecSymmetricDefault {
		return nil, []error{
			kmserr.NewValidation(kmserr.CauseUnsupportedOperationException, "automatic rotation is supported only for symmetric keys"),
		}
	}

	symmetricKey, ok := key.(*cmk.SymmetricKey)
	if !ok {
		return nil, []error{
			kmserr.NewValidation(kmserr.CauseUnsupportedOperationException, "automatic rotation is supported only for symmetric keys"),
		}
	}

	keyRotationEnabled := symmetricKey.RotationPeriodInDays > 0
	var rotationPeriod *int32
	if keyRotationEnabled {
		rotationPeriod = &symmetricKey.RotationPeriodInDays
	}

	return &awskms.GetKeyRotationStatusOutput{
		KeyRotationEnabled:   keyRotationEnabled,
		RotationPeriodInDays: rotationPeriod,
	}, nil
}
