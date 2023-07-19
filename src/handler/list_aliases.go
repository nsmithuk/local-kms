package handler

import (
	"fmt"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/nsmithuk/local-kms/src/config"
	"github.com/nsmithuk/local-kms/src/data"
)

func (r *RequestHandler) ListAliases() Response {
	var body *kms.ListAliasesInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.ListAliasesInput{}
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

	if limit < 1 || limit > 100 {
		msg := fmt.Sprintf("1 validation error detected: Value '%d' at 'limit' failed to satisfy "+
			"constraint: Minimum value of 1. Maximum value of 100.", limit)

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg)
	}

	// A valid Marker is check post data lookup.

	//--------------------------------

	var keyFilter string

	if body.KeyId != nil {

		target := config.EnsureArn("key/", *r.accountId, *body.KeyId)

		// Lookup the key
		key, _ := r.database.LoadKey(target)

		if key == nil {
			msg := fmt.Sprintf("Key '%s' does not exist", target)

			r.logger.Warnf(msg)
			return NewNotFoundExceptionResponse(msg)
		}

		//---

		keyFilter = key.GetMetadata().KeyId
	}

	//--------------------------------

	// Return 1 extra result to determine if there are > limit
	aliases, err := r.database.ListAlias(config.ArnPrefix(*r.accountId)+"alias/", limit+1, marker, keyFilter)
	if err != nil {

		if _, ok := err.(*data.InvalidMarkerExceptionError); ok {
			r.logger.Warnf("Invalid marker passed")
			return New400ExceptionResponse("InvalidMarkerException", "")
		}

		r.logger.Error(err)
		return NewInternalFailureExceptionResponse(err.Error())
	}

	//---

	type AliasList struct {
		AliasArn    string
		AliasName   string
		TargetKeyId string
	}

	response := &struct {
		NextMarker string `json:",omitempty"`
		Truncated  bool
		Aliases    []*AliasList
	}{}

	// If there are more than the limit, return the 'next' ID as the NextMarker
	if int64(len(aliases)) > limit {
		response.Truncated = true
		response.NextMarker = aliases[len(aliases)-1].AliasArn

		// Strip out the extra result.
		aliases = aliases[:limit]
	}

	response.Aliases = make([]*AliasList, len(aliases))

	for i, alias := range aliases {
		response.Aliases[i] = &AliasList{
			AliasArn:    alias.AliasArn,
			AliasName:   alias.AliasName,
			TargetKeyId: alias.TargetKeyId,
		}
	}

	//---

	r.logger.Infof("%d aliases listed\n", len(aliases))

	return NewResponse(200, response)
}
