package kms

import (
	"context"
	"errors"
	"time"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/nsmithuk/local-kms/internal/kms/data"
	"github.com/nsmithuk/local-kms/internal/kms/kmserr"
)

func (k KmsService) ScheduleKeyDeletion(ctx context.Context, req awskms.ScheduleKeyDeletionInput) (*awskms.ScheduleKeyDeletionOutput, []error) {

	// The default
	var pendingWindowInDays int32 = 30

	if req.PendingWindowInDays != nil {
		pendingWindowInDays = *req.PendingWindowInDays
	}

	if pendingWindowInDays < 7 || pendingWindowInDays > 30 {
		return nil, []error{
			kmserr.NewValidation(kmserr.CauseValidationError, "Value '%d' at 'PendingWindowInDays' failed to satisfy "+
				"constraint: Member must have minimum value of 7 and maximum value of 30.", pendingWindowInDays),
		}
	}

	//---

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

	//---

	if key.IsPendingDeletion() {
		return nil, []error{
			kmserr.NewValidation(kmserr.CauseKMSInvalidStateException, "%s is already scheduled for deletion", keyId),
		}
	}

	//---

	deletionDate := time.Now().AddDate(0, 0, int(pendingWindowInDays))

	key.GetMetadata().Enabled = false
	key.GetMetadata().KeyState = types.KeyStatePendingDeletion
	key.GetMetadata().DeletionDate = &deletionDate

	//----------------------------
	// Save the key

	err = k.Db.SaveKey(key)
	if err != nil {
		return nil, []error{err}
	}

	//---

	return &awskms.ScheduleKeyDeletionOutput{
		KeyId:               key.GetMetadata().Arn,
		KeyState:            key.GetMetadata().KeyState,
		DeletionDate:        key.GetMetadata().DeletionDate,
		PendingWindowInDays: &pendingWindowInDays,
	}, nil
}
