package handler

import (
	"fmt"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/nsmithuk/local-kms/src/config"
	"github.com/nsmithuk/local-kms/src/data"
)

/*
Note: Tags can be viewed even if a key is disabled or pending deletion.
*/

func (r *RequestHandler) ListResourceTags() Response {

	var body *kms.ListResourceTagsInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.ListResourceTagsInput{}
	}

	//---

	var marker string
	var limit int64 = 50

	if body.Marker != nil {
		marker = *body.Marker
	}
	if body.Limit != nil {
		limit = *body.Limit
	}

	//--------------------------------
	// Validation

	if limit < 1 || limit > 50 {
		msg := fmt.Sprintf("1 validation error detected: Value '%d' at 'limit' failed to satisfy "+
			"constraint: Minimum value of 1. Maximum value of 50.", limit)

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg)
	}

	if body.KeyId == nil {
		msg := "KeyId is a required parameter"

		r.logger.Warnf(msg)
		return NewMissingParameterResponse(msg)
	}

	keyId := config.EnsureArn("key/", *r.accountId, *body.KeyId)

	key, _ := r.database.LoadKey(keyId)

	if key == nil {
		msg := fmt.Sprintf("Key '%s' does not exist", keyId)
		r.logger.Warnf(msg)

		return NewNotFoundExceptionResponse(msg)
	}

	//---

	// Load the tags for the key
	tags, err := r.database.ListTags(key.GetArn(), limit+1, marker)

	//---

	response := &struct {
		NextMarker string `json:",omitempty"`
		Truncated  bool
		Tags       []*data.Tag
	}{}

	// If there are more than the limit, return the 'next' ID as the NextMarker
	if int64(len(tags)) > limit {
		response.Truncated = true
		response.NextMarker = tags[len(tags)-1].TagKey

		// Strip out the extra result.
		tags = tags[:limit]
	}

	response.Tags = tags

	r.logger.Infof("%d tags listed for key %s\n", len(tags), key.GetMetadata().Arn)

	return NewResponse(200, response)
}
