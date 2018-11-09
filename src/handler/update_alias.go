package handler

import (
	"github.com/aws/aws-sdk-go/service/kms"
	"strings"
	"github.com/nsmithuk/local-kms/src/config"
	"fmt"
)

func (r *RequestHandler) UpdateAlias() Response {

	var body *kms.UpdateAliasInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.UpdateAliasInput{}
	}

	//--------------------------------
	// Validation

	if body.TargetKeyId == nil {
		msg := "TargetKeyId is a required parameter"

		r.logger.Warnf(msg)
		return NewMissingParameterResponse(msg)
	}

	if body.AliasName == nil {
		msg := "AliasName is a required parameter"

		r.logger.Warnf(msg)
		return NewMissingParameterResponse(msg)
	}

	if !strings.HasPrefix(*body.AliasName, "alias/") {
		msg := "Alias must start with the prefix \"alias/\". Please see " +
			"http://docs.aws.amazon.com/kms/latest/developerguide/programming-aliases.html"

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg)
	}

	if strings.HasPrefix(*body.AliasName, "alias/aws") {
		r.logger.Warnf("Cannot create alias with prefix 'alias/aws/'")
		return NewNotAuthorizedExceptionResponse( "")
	}

	if len(*body.AliasName) > 256 {
		msg := fmt.Sprintf("1 validation error detected: Value '%s' at 'AliasName' failed to satisfy " +
			"constraint: Member must have length less than or equal to 256", *body.AliasName)

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg)
	}

	//---

	aliasArn := config.ArnPrefix() + *body.AliasName

	alias, err := r.database.LoadAlias(aliasArn)

	if err != nil {
		msg := fmt.Sprintf("Alias '%s' does not exist", *body.AliasName)

		r.logger.Warnf(msg)
		return NewNotFoundExceptionResponse(msg)
	}

	//---

	keyArn := config.EnsureArn("key/", *body.TargetKeyId)

	// Lookup the key
	key, _ := r.database.LoadKey(keyArn)

	if key == nil {
		msg := fmt.Sprintf("Key '%s' does not exist", keyArn)

		r.logger.Warnf(msg)
		return NewNotFoundExceptionResponse(msg)
	}

	//---

	if key.Metadata.DeletionDate != 0 {
		// Key is pending deletion; cannot create alias
		msg := fmt.Sprintf("%s is pending deletion.", keyArn)

		r.logger.Warnf(msg)
		return NewKMSInvalidStateExceptionResponse(msg)
	}

	//---

	alias.TargetKeyId = key.Metadata.KeyId

	r.database.SaveAlias(alias)

	//---

	r.logger.Infof("Alias updated: %s -> %s\n", alias.AliasArn, key.Metadata.Arn)

	return NewResponse(200, nil)
}
