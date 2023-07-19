package handler

import (
	"fmt"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/nsmithuk/local-kms/src/cmk"
	"github.com/nsmithuk/local-kms/src/config"
	"time"
)

func (r *RequestHandler) DisableKeyRotation() Response {

	var body *kms.DisableKeyRotationInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.DisableKeyRotationInput{}
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

	// Check the key supports rotation
	if key.GetMetadata().Origin == cmk.KeyOriginExternal {
		msg := fmt.Sprintf("%s origin is EXTERNAL which is not valid for this operation.", key.GetArn())

		r.logger.Warnf(msg)
		return NewUnsupportedOperationException(msg)
	}

	if _, ok := key.(*cmk.AesKey); !ok {

		r.logger.Warnf(fmt.Sprintf("Key '%s' does does not support rotation", keyArn))

		// I suspect that it's an error to return a 200, but it is what AWS currently do.
		return NewResponse(200, nil)

		// This is what I'd expect:
		//return NewUnsupportedOperationException("")
	}

	//---

	if key.GetMetadata().DeletionDate != 0 {
		// Key is pending deletion; cannot create alias
		msg := fmt.Sprintf("%s is pending deletion.", keyArn)

		r.logger.Warnf(msg)
		return NewKMSInvalidStateExceptionResponse(msg)
	}

	//---

	if !key.GetMetadata().Enabled {
		// Key is pending deletion; cannot create alias
		msg := fmt.Sprintf("%s is disabled.", keyArn)

		r.logger.Warnf(msg)
		return NewDisabledExceptionResponse(msg)
	}

	//---

	// Disable by setting this to Time Zero.
	key.(*cmk.AesKey).NextKeyRotation = time.Time{}

	//--------------------------------
	// Save the key

	err = r.database.SaveKey(key)
	if err != nil {
		r.logger.Error(err)
		return NewInternalFailureExceptionResponse(err.Error())
	}

	//---

	r.logger.Infof("Key rotation disabled: %s\n", key.GetMetadata().Arn)

	return NewResponse(200, nil)
}
