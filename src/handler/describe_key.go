package handler

import (
	"fmt"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/nsmithuk/local-kms/src/cmk"
	"github.com/nsmithuk/local-kms/src/config"
	"strings"
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

	var keyId = *body.KeyId

	//---

	// If it's an alias, map it to a key
	if strings.Contains(keyId, "alias/") {
		aliasArn := config.EnsureArn("", *body.KeyId)

		alias, err := r.database.LoadAlias(aliasArn)

		if err != nil {
			msg := fmt.Sprintf("Alias '%s' does not exist", keyId)

			r.logger.Warnf(msg)
			return NewNotFoundExceptionResponse(msg)
		}

		keyId = alias.TargetKeyId
	}

	//---

	// Lookup the key
	keyId = config.EnsureArn("key/", keyId)

	key, err := r.database.LoadKey(keyId)

	if key == nil {
		msg := fmt.Sprintf("error loading key: %s", err.Error())
		r.logger.Errorf(msg)

		return NewNotFoundExceptionResponse(msg)
	}

	//---

	response := map[string]*cmk.KeyMetadata{
		"KeyMetadata": key.GetMetadata(),
	}

	//---

	r.logger.Infof("Key described: %s\n", key.GetArn())

	return NewResponse( 200, response)
}
