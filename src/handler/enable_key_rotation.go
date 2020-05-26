package handler

import (
	"fmt"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/nsmithuk/local-kms/src/cmk"
	"github.com/nsmithuk/local-kms/src/config"
	"time"
)

func (r *RequestHandler) EnableKeyRotation() Response {

	var body *kms.EnableKeyRotationInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.EnableKeyRotationInput{}
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

	// Check the key supports rotation
	if _,ok := key.(*cmk.AesKey); !ok {
		r.logger.Warnf(fmt.Sprintf("Key '%s' does does not support rotation", keyArn))

		return NewUnsupportedOperationException("")
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

	// If it's already enabled, don't reset it to another year. TODO - is this correct?
	if key.(*cmk.AesKey).NextKeyRotation.IsZero() {
		key.(*cmk.AesKey).NextKeyRotation = time.Now().AddDate(1, 0, 0)
	}

	// To allow testing...
	//key.NextKeyRotation = time.Now().Add( time.Second * 10 )

	//--------------------------------
	// Save the key

	err = r.database.SaveKey(key)
	if err != nil {
		r.logger.Error(err)
		return NewInternalFailureExceptionResponse(err.Error())
	}

	//---

	r.logger.Infof("Key rotation enabled: %s\n", key.GetArn())

	return NewResponse( 200, nil)
}
