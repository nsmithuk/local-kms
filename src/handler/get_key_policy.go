package handler

import (
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/nsmithuk/local-kms/src/config"
	"fmt"
)

func (r *RequestHandler) GetKeyPolicy() Response {

	var body *kms.GetKeyPolicyInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.GetKeyPolicyInput{}
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

	r.logger.Infof("Key policy returned: %s\n", key.Metadata.Arn)

	return NewResponse( 200, map[string]string{
		"Policy": key.Policy,
	})
}
