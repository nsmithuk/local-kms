package handler

import (
	"fmt"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/nsmithuk/local-kms/src/config"
	"github.com/nsmithuk/local-kms/src/data"
)

func (r *RequestHandler) ListKeys() Response {

	var body *kms.ListKeysInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.ListKeysInput{}
	}

	//---

	var marker string
	var limit int64 = 100

	if body.Marker != nil { marker = *body.Marker }
	if body.Limit != nil { limit = *body.Limit }

	//--------------------------------
	// Validation

	if limit < 1 || limit > 1000 {
		msg := fmt.Sprintf("1 validation error detected: Value '%d' at 'limit' failed to satisfy " +
			"constraint: Minimum value of 1. Maximum value of 1000.", limit)

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg)
	}

	// A valid Marker is check post data lookup.

	//---

	// Return 1 extra result to determine if there are > limit
	keys, err := r.database.ListKeys(config.ArnPrefix() + "key/", limit + 1, marker)
	if err != nil {

		if _, ok := err.(*data.InvalidMarkerExceptionError); ok {
			r.logger.Warnf("Invalid marker passed")
			return New400ExceptionResponse("InvalidMarkerException", "")
		}

		r.logger.Error(err)
		return NewInternalFailureExceptionResponse(err.Error())
	}

	//---

	type ListKeysOutputKey struct {
		KeyArn string
		KeyId string
	}

	response := &struct {
		NextMarker 	string `json:",omitempty"`
		Truncated 	bool
		Keys 		[]*ListKeysOutputKey
	}{}


	// If there are more than the limit, return the 'next' ID as the NextMarker
	if int64(len(keys)) > limit {
		response.Truncated = true
		response.NextMarker = keys[len(keys)-1].Metadata.Arn

		// Strip out the extra result.
		keys = keys[:limit]
	}

	response.Keys = make([]*ListKeysOutputKey, len(keys))

	for i, key := range keys {
		response.Keys[i] = &ListKeysOutputKey{
			KeyArn: key.Metadata.Arn,
			KeyId: key.Metadata.KeyId,
		}
	}

	//---

	r.logger.Infof("%d keys listed\n", len(keys))

	return NewResponse( 200, response)
}
