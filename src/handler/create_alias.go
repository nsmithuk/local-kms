package handler

import (
	"fmt"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/nsmithuk/local-kms/src/config"
	"github.com/nsmithuk/local-kms/src/data"
	"strings"
)

func (r *RequestHandler) CreateAlias() Response {

	var body *kms.CreateAliasInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.CreateAliasInput{}
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
		return NewNotAuthorizedExceptionResponse("")
	}

	if len(*body.AliasName) > 256 {
		msg := fmt.Sprintf("1 validation error detected: Value '%s' at 'AliasName' failed to satisfy "+
			"constraint: Member must have length less than or equal to 256", *body.AliasName)

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg)
	}

	// --------------------------------

	target := config.EnsureArn("key/", *r.accountId, *body.TargetKeyId)

	// Lookup the key
	key, _ := r.database.LoadKey(target)

	if key == nil {
		msg := fmt.Sprintf("Key '%s' does not exist", target)

		r.logger.Warnf(msg)
		return NewNotFoundExceptionResponse(msg)
	}

	//---

	if key.GetMetadata().DeletionDate != 0 {
		// Key is pending deletion; cannot create alias
		msg := fmt.Sprintf("%s is pending deletion.", target)

		r.logger.Warnf(msg)
		return NewKMSInvalidStateExceptionResponse(msg)
	}

	//---

	aliasArn := config.ArnPrefix(*r.accountId) + *body.AliasName

	_, err = r.database.LoadAlias(aliasArn)

	if err == nil {
		msg := fmt.Sprintf("An alias with the name %s already exists", aliasArn)

		r.logger.Warnf(msg)
		return NewAlreadyExistsExceptionResponse(msg)
	}

	alias := &data.Alias{
		AliasName:   *body.AliasName,
		AliasArn:    aliasArn,
		TargetKeyId: key.GetMetadata().KeyId,
	}

	r.database.SaveAlias(alias)

	r.logger.Infof("New alias created: %s -> %s\n", alias.AliasArn, key.GetArn())

	return NewResponse(200, nil)
}
