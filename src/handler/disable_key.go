package handler

import (
	"fmt"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/nsmithuk/local-kms/src/config"
)

func (r *RequestHandler) DisableKey() Response {

	var body *kms.DisableKeyInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.DisableKeyInput{}
	}

	//--------------------------------
	// Validation

	if body.KeyId == nil {
		msg := "KeyId is a required parameter"

		r.logger.Warnf(msg)
		return NewMissingParameterResponse(msg)
	}

	//---

	keyArn := config.EnsureArn("key/", *body.KeyId)

	// Lookup the key
	key, _ := r.database.LoadKey(keyArn)

	if key == nil {
		msg := fmt.Sprintf("Key '%s' does not exist", keyArn)

		r.logger.Warnf(msg)
		return NewNotFoundExceptionResponse(msg)
	}

	//---

	if key.Metadata.DeletionDate != 0 {
		// Key is pending deletion; cannot create alias
		msg := fmt.Sprintf("%s is pending deletion.", keyArn)

		r.logger.Warnf(msg)
		return NewKMSInvalidStateExceptionResponse(msg)
	}

	//---

	key.Metadata.Enabled = false
	key.Metadata.KeyState = "Disabled"

	//--------------------------------
	// Save the key

	err = r.database.SaveKey(key)
	if err != nil {
		r.logger.Error(err)
		return NewInternalFailureExceptionResponse(err.Error())
	}

	//---

	r.logger.Infof("Key disabled: %s\n", key.Metadata.Arn)

	return NewResponse( 200, nil)

}
