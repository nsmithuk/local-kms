package kms

import (
	"context"
	"errors"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/nsmithuk/local-kms/internal/kms/data"
	"github.com/nsmithuk/local-kms/internal/kms/kmserr"
)

func (k KmsService) CancelKeyDeletion(ctx context.Context, req awskms.CancelKeyDeletionInput) (*awskms.CancelKeyDeletionOutput, []error) {
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

	if !key.IsPendingDeletion() {
		return nil, []error{
			kmserr.NewValidation(kmserr.CauseKMSInvalidStateException, "%s is not pending deletion.", key.GetArn()),
		}
	}

	key.GetMetadata().DeletionDate = nil
	key.GetMetadata().PendingDeletionWindowInDays = nil
	key.GetMetadata().Enabled = false
	key.GetMetadata().KeyState = types.KeyStateDisabled

	if err := k.Db.SaveKey(key); err != nil {
		return nil, []error{err}
	}

	return &awskms.CancelKeyDeletionOutput{
		KeyId: key.GetMetadata().Arn,
	}, nil
}
