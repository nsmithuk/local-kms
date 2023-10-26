package handler

import (
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/nsmithuk/local-kms/src/cmk"
	"github.com/nsmithuk/local-kms/src/config"
)

func (r *RequestHandler) ScheduleKeyDeletion() Response {

	var body *kms.ScheduleKeyDeletionInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.ScheduleKeyDeletionInput{}
	}

	//--------------------------------
	// Validation

	if body.KeyId == nil {
		msg := "KeyId is a required parameter"

		r.logger.Warnf(msg)
		return NewMissingParameterResponse(msg)
	}

	var PendingWindowInDays int64

	if body.PendingWindowInDays != nil {
		PendingWindowInDays = *body.PendingWindowInDays

		if PendingWindowInDays < 7 || PendingWindowInDays > 30 {
			msg := fmt.Sprintf("1 validation error detected: Value '%d' at 'PendingWindowInDays' failed to satisfy "+
				"constraint: Member must have minimum value of 7 and maximum value of 30.", *body.PendingWindowInDays)

			r.logger.Warnf(msg)
			return NewValidationExceptionResponse(msg)
		}
	} else {
		PendingWindowInDays = 30
	}

	//---

	target := config.EnsureArn("key/", *r.accountId, *body.KeyId)

	// Lookup the key
	key, _ := r.database.LoadKey(target)

	if key == nil {
		msg := fmt.Sprintf("Key '%s' does not exist", target)

		r.logger.Warnf(msg)
		return NewNotFoundExceptionResponse(msg)
	}

	//---

	if key.GetMetadata().DeletionDate != 0 {
		// Key is pending deletion; cannot re-schedule
		msg := fmt.Sprintf("%s is pending deletion.", target)

		r.logger.Warnf(msg)
		return NewKMSInvalidStateExceptionResponse(msg)
	}

	//---

	key.GetMetadata().Enabled = false
	key.GetMetadata().KeyState = cmk.KeyStatePendingDeletion
	key.GetMetadata().DeletionDate = time.Now().AddDate(0, 0, int(PendingWindowInDays)).Unix()

	//--------------------------------
	// Save the key

	err = r.database.SaveKey(key)
	if err != nil {
		r.logger.Error(err)
		return NewInternalFailureExceptionResponse(err.Error())
	}

	//---

	r.logger.Infof("Schedule key deletion: %s\n", key.GetArn())

	return NewResponse(200, map[string]interface{}{
		"KeyId":        key.GetArn(),
		"DeletionDate": key.GetMetadata().DeletionDate,
	})
}
