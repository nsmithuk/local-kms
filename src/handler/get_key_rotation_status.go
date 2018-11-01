package handler

import (
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/NSmithUK/local-kms-go/src/config"
	"fmt"
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

	keyArn := config.EnsureArn("key/", *body.KeyId)

	// Lookup the key
	key, _ := r.database.LoadKey(keyArn)

	if key == nil {
		msg := fmt.Sprintf("Key '%s' does not exist", keyArn)

		r.logger.Warnf(msg)
		return NewNotFoundExceptionResponse(msg)
	}

	//---

	return NewResponse( 200, map[string]bool{
		"KeyRotationEnabled": !key.NextKeyRotation.IsZero(),
	})
}
