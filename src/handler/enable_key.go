package handler

import (
	"fmt"

	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/nsmithuk/local-kms/src/cmk"
	"github.com/nsmithuk/local-kms/src/config"
)

func (r *RequestHandler) EnableKey() Response {

	var body *kms.EnableKeyInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.EnableKeyInput{}
	}

	//--------------------------------
	// Validation

	if body.KeyId == nil {
		msg := "KeyId is a required parameter"

		r.logger.Warnf(msg)
		return NewMissingParameterResponse(msg)
	}

	//---

	keyArn := config.EnsureArn("key/", *r.accountId, *body.KeyId)

	// Lookup the key
	key, _ := r.database.LoadKey(keyArn)

	if key == nil {
		msg := fmt.Sprintf("Key '%s' does not exist", keyArn)

		r.logger.Warnf(msg)
		return NewNotFoundExceptionResponse(msg)
	}

	//---

	if key.GetMetadata().DeletionDate != 0 {
		// Key is pending deletion; cannot create alias
		msg := fmt.Sprintf("%s is pending deletion.", keyArn)

		r.logger.Warnf(msg)
		return NewKMSInvalidStateExceptionResponse(msg)
	}

	//---

	key.GetMetadata().Enabled = true
	key.GetMetadata().KeyState = cmk.KeyStateEnabled

	//--------------------------------
	// Save the key

	err = r.database.SaveKey(key)
	if err != nil {
		r.logger.Error(err)
		return NewInternalFailureExceptionResponse(err.Error())
	}

	//---

	r.logger.Infof("Key enabled: %s\n", key.GetArn())

	return NewResponse(200, nil)

}
