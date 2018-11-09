package handler

import (
	"github.com/aws/aws-sdk-go/service/kms"
	"strings"
	"github.com/nsmithuk/local-kms/src/data"
	"github.com/nsmithuk/local-kms/src/config"
	"fmt"
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

	key, _ := r.database.LoadKey(keyId)

	if key == nil {
		msg := fmt.Sprintf("Key '%s' does not exist", keyId)

		r.logger.Warnf(msg)
		return NewNotFoundExceptionResponse(msg)
	}

	//---

	response := map[string]data.KeyMetadata{
		"KeyMetadata": key.Metadata,
	}

	//---

	r.logger.Infof("Key described: %s\n", key.Metadata.Arn)

	return NewResponse( 200, response)
}
