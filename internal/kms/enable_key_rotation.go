package kms

import (
	"context"
	"time"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/nsmithuk/local-kms/internal/kms/cmk"
	"github.com/nsmithuk/local-kms/internal/kms/kmserr"
)

func (k KmsService) EnableKeyRotation(ctx context.Context, req awskms.EnableKeyRotationInput) (*awskms.EnableKeyRotationOutput, []error) {
	key, err := k.getUsableKey(req.KeyId)
	if err != nil {
		return nil, []error{err}
	}

	if key.GetMetadata().Origin == types.OriginTypeExternal {
		return nil, []error{
			kmserr.NewValidation(kmserr.CauseUnsupportedOperationException, "automatic rotation is not supported for imported key material"),
		}
	}

	symmetricKey, ok := key.(*cmk.SymmetricKey)
	if !ok {
		return nil, []error{
			kmserr.NewValidation(kmserr.CauseUnsupportedOperationException, "automatic rotation is supported only for symmetric keys"),
		}
	}

	rotationPeriodInDays := int32(365)
	if req.RotationPeriodInDays != nil {
		if *req.RotationPeriodInDays < 1 {
			return nil, []error{
				kmserr.NewValidation(kmserr.CauseValidationError, "RotationPeriodInDays must be greater than 0"),
			}
		}
		rotationPeriodInDays = *req.RotationPeriodInDays
	}

	symmetricKey.RotationPeriodInDays = rotationPeriodInDays
	symmetricKey.NextKeyRotation = time.Now().AddDate(0, 0, int(rotationPeriodInDays))

	if err := k.Db.SaveKey(symmetricKey); err != nil {
		return nil, []error{err}
	}

	return &awskms.EnableKeyRotationOutput{}, nil
}
