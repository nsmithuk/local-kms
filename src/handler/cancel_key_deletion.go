package handler

import (
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/nsmithuk/local-kms/src/config"
	"fmt"
)

func (r *RequestHandler) CancelKeyDeletion() Response {

	var body *kms.CancelKeyDeletionInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.CancelKeyDeletionInput{}
	}

	//--------------------------------
	// Validation

	if body.KeyId == nil {
		msg := "KeyId is a required parameter"

		r.logger.Warnf(msg)
		return NewMissingParameterResponse(msg)
	}

	//---

	target := config.EnsureArn("key/", *body.KeyId)

	// Lookup the key
	key, _ := r.database.LoadKey(target)

	if key == nil {
		msg := fmt.Sprintf("Key '%s' does not exist", target)

		r.logger.Warnf(msg)
		return NewNotFoundExceptionResponse(msg)
	}

	//---

	if key.Metadata.DeletionDate == 0 {
		// Key is pending deletion; cannot re-schedule
		msg := fmt.Sprintf("%s is not pending deletion.", target)

		r.logger.Warnf(msg)
		return NewKMSInvalidStateExceptionResponse(msg)
	}

	//---

	key.Metadata.Enabled = true
	key.Metadata.KeyState = "Enabled"
	key.Metadata.DeletionDate = 0

	//--------------------------------
	// Save the key

	err = r.database.SaveKey(key)
	if err != nil {
		r.logger.Error(err)
		return NewInternalFailureExceptionResponse(err.Error())
	}

	//---

	return NewResponse( 200, map[string]interface{}{
		"KeyId": key.Metadata.Arn,
	})
}
