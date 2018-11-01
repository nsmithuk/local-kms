package handler

import (
	"github.com/aws/aws-sdk-go/service/kms"
	"strings"
	"github.com/NSmithUK/local-kms-go/src/config"
	"fmt"
	"github.com/NSmithUK/local-kms-go/src/service"
	"github.com/davecgh/go-spew/spew"
)

func (r *RequestHandler) Encrypt() Response {

	var body *kms.EncryptInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.EncryptInput{}
	}

	//--------------------------------
	// Validation

	if body.KeyId == nil {
		msg := "KeyId is a required parameter"

		r.logger.Warnf(msg)
		return NewMissingParameterResponse(msg)
	}

	if len(body.Plaintext) == 0 {
		msg := "Plaintext is a required parameter"

		r.logger.Warnf(msg)
		return NewMissingParameterResponse(msg)
	}

	if len(body.Plaintext) > 4096 {
		msg := fmt.Sprintf("1 validation error detected: Value '%s' at 'Plaintext' failed to satisfy " +
			"constraint: Member must have length minimum length of 1 and maximum length of 4096.", string(body.Plaintext))

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg)
	}

	//----------------------------------

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

	//----------------------------------

	if key.Metadata.DeletionDate != 0 {
		// Key is pending deletion; cannot create alias
		msg := fmt.Sprintf("%s is pending deletion.", keyId)

		r.logger.Warnf(msg)
		return NewKMSInvalidStateExceptionResponse(msg)
	}

	if !key.Metadata.Enabled {
		// Key is pending deletion; cannot create alias
		msg := fmt.Sprintf("%s is disabled.", keyId)

		r.logger.Warnf(msg)
		return NewDisabledExceptionResponse(msg)
	}

	//----------------------------------

	keyVersion := len(key.BackingKeys) - 1

	dataKey := key.BackingKeys[keyVersion]

	ciphertext, err := service.Encrypt(dataKey, body.Plaintext)

	cipherResponse := service.ConstructCipherResponse(key.Metadata.Arn, uint32(keyVersion), ciphertext)

	spew.Dump(cipherResponse)
	spew.Dump(string(cipherResponse))

	response := &struct {
		KeyId			string
		CiphertextBlob	[]byte
	}{
		KeyId: key.Metadata.Arn,
		CiphertextBlob: cipherResponse,
	}

	return NewResponse( 200, response)
}
