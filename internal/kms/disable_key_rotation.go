package kms

import (
	"context"
	"time"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/nsmithuk/local-kms/internal/kms/cmk"
	"github.com/nsmithuk/local-kms/internal/kms/kmserr"
)

func (k KmsService) DisableKeyRotation(ctx context.Context, req awskms.DisableKeyRotationInput) (*awskms.DisableKeyRotationOutput, []error) {
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

	symmetricKey.RotationPeriodInDays = 0
	symmetricKey.NextKeyRotation = time.Time{}

	if err := k.Db.SaveKey(symmetricKey); err != nil {
		return nil, []error{err}
	}

	return &awskms.DisableKeyRotationOutput{}, nil
}
