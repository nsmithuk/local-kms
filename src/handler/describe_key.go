package handler

import (
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/nsmithuk/local-kms/src/cmk"
)

func (r *RequestHandler) DescribeKey() Response {

	var body *kms.ScheduleKeyDeletionInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.ScheduleKeyDeletionInput{}
	}

	//--------------------------------
	// Validation

	if body.KeyId == nil {
		msg := "KeyId is a required parameter"

		r.logger.Warnf(msg)
		return NewMissingParameterResponse(msg)
	}

	//---

	key, errResponse := r.getKey(*body.KeyId)
	if !errResponse.Empty() {
		return errResponse
	}

	//---

	response := map[string]*cmk.KeyMetadata{
		"KeyMetadata": key.GetMetadata(),
	}

	//---

	r.logger.Infof("Key described: %s\n", key.GetArn())

	return NewResponse(200, response)
}
