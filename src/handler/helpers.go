package handler

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/nsmithuk/local-kms/src/cmk"
	"github.com/nsmithuk/local-kms/src/config"
)

/*
Finds a key for a given key or alias name or ARN
*/
func (r *RequestHandler) getKey(keyId string) (cmk.Key, Response) {

	// If it's an alias, map it to a key
	if strings.Contains(keyId, "alias/") {
		aliasArn := config.EnsureArn("", *r.accountId, keyId)

		alias, err := r.database.LoadAlias(aliasArn)

		if err != nil {
			msg := fmt.Sprintf("Alias %s is not found.", config.ArnPrefix(*r.accountId)+keyId)

			r.logger.Warnf(msg)
			return nil, NewNotFoundExceptionResponse(msg)
		}

		keyId = alias.TargetKeyId
	}

	//---

	// Lookup the key
	keyId = config.EnsureArn("key/", *r.accountId, keyId)

	key, _ := r.database.LoadKey(keyId)

	if key == nil {
		msg := fmt.Sprintf("Key '%s' does not exist", keyId)
		r.logger.Warnf(msg)

		return nil, NewNotFoundExceptionResponse(msg)
	}

	return key, Response{}
}

/*
Finds a key for a given key or alias name or ARN
And confirms that it's available to use for cryptographic operations.
*/
func (r *RequestHandler) getUsableKey(keyId string) (cmk.Key, Response) {

	key, response := r.getKey(keyId)
	if key == nil {
		return nil, response
	}

	//----------------------------------

	if key.GetMetadata().KeyState == cmk.KeyStatePendingImport {
		// Key material hasn't been imported
		msg := fmt.Sprintf("%s is pending import.", keyId)

		r.logger.Warnf(msg)
		return nil, NewKMSInvalidStateExceptionResponse(msg)
	}

	if key.GetMetadata().DeletionDate != 0 {
		// Key is pending deletion; cannot create alias
		msg := fmt.Sprintf("%s is pending deletion.", keyId)

		r.logger.Warnf(msg)
		return nil, NewKMSInvalidStateExceptionResponse(msg)
	}

	if !key.GetMetadata().Enabled {
		// Key is pending deletion; cannot create alias
		msg := fmt.Sprintf("%s is disabled.", keyId)

		r.logger.Warnf(msg)
		return nil, NewDisabledExceptionResponse(msg)
	}

	return key, Response{}
}

func (r *RequestHandler) validateTags(tags []*kms.Tag) Response {
	if tags != nil && len(tags) > 0 {
		for i, kv := range tags {

			if len(*kv.TagKey) < 1 {
				msg := fmt.Sprintf("1 validation error detected: Value '' at 'tags.%d.member.tagKey' failed to "+
					"satisfy constraint: Member must have length greater than or equal to 1", i+1)

				r.logger.Warnf(msg)
				return NewValidationExceptionResponse(msg)
			}

			if len(*kv.TagKey) > 128 {
				msg := fmt.Sprintf("1 validation error detected: Value '' at 'tags.%d.member.tagKey' failed to "+
					"satisfy constraint: Member must have length less than or equal to 128", i+1)

				r.logger.Warnf(msg)
				return NewValidationExceptionResponse(msg)
			}

			if len(*kv.TagValue) > 256 {
				msg := fmt.Sprintf("1 validation error detected: Value '' at 'tags.%d.member.tagValue' failed to "+
					"satisfy constraint: Member must have length less than or equal to 256", i+1)

				r.logger.Warnf(msg)
				return NewValidationExceptionResponse(msg)
			}

			// TagValue is allowed to have len == 0
		}
	}

	// Return an empty response if all is well
	return Response{}
}
