package handler

import "github.com/aws/aws-sdk-go/service/kms"

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

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg)
	}

	if body.TagKeys == nil {
		msg := "1 validation error detected: Value null at 'tagKeys' failed to satisfy constraint: Member must not be null"

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg)
	}

	//---

	key, response := r.getUsableKey(*body.KeyId)
	if !response.Empty() {
		return response
	}

	//---

	if len(body.TagKeys) > 0 {
		for _, k := range body.TagKeys {
			err = r.database.DeleteObject(key.GetArn() + "/tag/" + *k)
			r.logger.Infof("Tag deleted: %s\n", *k)
		}
	}

	return NewResponse(200, nil)
}
