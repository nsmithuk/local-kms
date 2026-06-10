package handler

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/nsmithuk/local-kms/src/cmk"
)

func (r *RequestHandler) UntagResource() Response {

	var body *kms.UntagResourceInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.UntagResourceInput{}
	}

	//--------------------------------
	// Validation

	if body.KeyId == nil {
		msg := "1 validation error detected: Value null at 'keyId' failed to satisfy constraint: Member must not be null"

		r.logger.Warn(msg)
		return NewValidationExceptionResponse(msg)
	}

	if body.TagKeys == nil {
		msg := "1 validation error detected: Value null at 'tagKeys' failed to satisfy constraint: Member must not be null"

		r.logger.Warn(msg)
		return NewValidationExceptionResponse(msg)
	}

	//---

	key, response := r.getKey(*body.KeyId)
	if !response.Empty() {
		return response
	}

	switch key.GetMetadata().KeyState {
	case cmk.KeyStatePendingDeletion:
		msg := fmt.Sprintf("%s is pending deletion.", *body.KeyId)

		r.logger.Warn(msg)
		return NewKMSInvalidStateExceptionResponse(msg)

	}

	//---

	if len(body.TagKeys) > 0 {
		for _, k := range body.TagKeys {
			err = r.database.DeleteObject(key.GetArn() + "/tag/" + k)
			if err != nil {
				r.logger.Warn(err)
			}
			r.logger.Infof("Tag deleted: %s\n", k)
		}
	}

	return NewResponse(200, nil)
}
