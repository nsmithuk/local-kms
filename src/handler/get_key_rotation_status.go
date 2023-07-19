package handler

import (
	"fmt"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/nsmithuk/local-kms/src/cmk"
	"github.com/nsmithuk/local-kms/src/config"
)

func (r *RequestHandler) GetKeyRotationStatus() Response {

	var body *kms.GetKeyRotationStatusInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.GetKeyRotationStatusInput{}
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

		// Hard code false for non-AES CMKs.
		return NewResponse(200, map[string]bool{
			"KeyRotationEnabled": false,
		})
	}

	//---

	r.logger.Infof("Key rotation status returned: %s\n", key.GetArn())

	return NewResponse(200, map[string]bool{
		"KeyRotationEnabled": !key.(*cmk.AesKey).NextKeyRotation.IsZero(),
	})
}
