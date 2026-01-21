package kms

import (
	"context"
	"errors"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/nsmithuk/local-kms/internal/kms/data"
	"github.com/nsmithuk/local-kms/internal/kms/kmserr"
)

func (k KmsService) EnableKey(ctx context.Context, req awskms.EnableKeyInput) (*awskms.EnableKeyOutput, []error) {
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

	key.GetMetadata().Enabled = true
	key.GetMetadata().KeyState = types.KeyStateEnabled

	if err := k.Db.SaveKey(key); err != nil {
		return nil, []error{err}
	}

	return &awskms.EnableKeyOutput{}, nil
}
