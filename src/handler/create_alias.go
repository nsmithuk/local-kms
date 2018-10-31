package handler

import (
	"github.com/NSmithUK/local-kms-go/src/config"
	"github.com/aws/aws-sdk-go/service/kms"
	"strings"
	"github.com/NSmithUK/local-kms-go/src/data"
	"fmt"
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

	if strings.HasPrefix(*body.AliasName, "alias/aws/") {
		r.logger.Warnf("Cannot create alias with prefix 'alias/aws/'")
		return NewNotAuthorizedExceptionResponse( "")
	}

	// TODO: Max alias name length of 256

	// --------------------------------

	target := config.EnsureArn("key/", *body.TargetKeyId)

	// Lookup the key
	key, _ := r.database.LoadKey(target)

	if key == nil {
		msg := fmt.Sprintf("Key '%s' does not exist", target)

		r.logger.Warnf(msg)
		return NewNotFoundExceptionResponse(msg)
	}

	//---

	if key.Metadata.DeletionDate != 0 {
		// Key is pending deletion; cannot create alias
		msg := fmt.Sprintf("%s is pending deletion.", target)

		r.logger.Warnf(msg)
		return NewKMSInvalidStateExceptionResponse(msg)
	}

	//---

	aliasArn :=  config.ArnPrefix() + *body.AliasName

	_, err = r.database.LoadAlias(aliasArn)

	if err == nil {
		msg := fmt.Sprintf("An alias with the name %s already exists", aliasArn)

		r.logger.Warnf(msg)
		return NewAlreadyExistsExceptionResponse(msg)
	}

	alias := &data.Alias{
		AliasName: *body.AliasName,
		AliasArn: aliasArn,
		TargetKeyId: key.Metadata.KeyId,
	}

	r.database.SaveAlias(alias)

	return NewResponse(200, nil)
}
