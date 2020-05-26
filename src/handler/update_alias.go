package handler

import (
	"fmt"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/nsmithuk/local-kms/src/config"
	"reflect"
	"strings"
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

	originalKeyArn := config.EnsureArn("key/", alias.TargetKeyId)

	// Lookup the key
	originalKey, _ := r.database.LoadKey(originalKeyArn)

	if originalKey == nil {
		msg := fmt.Sprintf("Original key '%s' does not exist", originalKeyArn)
		r.logger.Errorf(msg)
		return NewInternalFailureExceptionResponse(msg)
	}

	//---

	targetKeyArn := config.EnsureArn("key/", *body.TargetKeyId)

	// Lookup the key
	targetKey, _ := r.database.LoadKey(targetKeyArn)

	if targetKey == nil {
		msg := fmt.Sprintf("Key '%s' does not exist", targetKeyArn)

		r.logger.Warnf(msg)
		return NewNotFoundExceptionResponse(msg)
	}

	//---

	// Key usage cannot change
	if originalKey.GetMetadata().KeyUsage != targetKey.GetMetadata().KeyUsage {
		msg := fmt.Sprintf("Alias %s cannot be changed from a CMK with key usage %s to a CMK with key " +
			"usage %s. The key usage of the current CMK and the new CMK must be the same.",
			*body.AliasName, originalKey.GetMetadata().KeyUsage, targetKey.GetMetadata().KeyUsage)

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg)
	}

	// Key type cannot change
	if reflect.TypeOf(originalKey) != reflect.TypeOf(targetKey) {

		// TODO The wording of this validation message needs amending to match AWS.
		msg := fmt.Sprintf("Alias %s cannot be changed from a CMK with key type %s to a CMK with key " +
			"type %s. The key type of the current CMK and the new CMK must be the same.",
			*body.AliasName, reflect.TypeOf(originalKey), reflect.TypeOf(targetKey))

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg)
	}

	//---

	if targetKey.GetMetadata().DeletionDate != 0 {
		// Key is pending deletion; cannot create alias
		msg := fmt.Sprintf("%s is pending deletion.", targetKeyArn)

		r.logger.Warnf(msg)
		return NewKMSInvalidStateExceptionResponse(msg)
	}

	//---

	alias.TargetKeyId = targetKey.GetMetadata().KeyId

	r.database.SaveAlias(alias)

	//---

	r.logger.Infof("Alias updated: %s -> %s\n", alias.AliasArn, targetKey.GetArn())

	return NewResponse(200, nil)
}
