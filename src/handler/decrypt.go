package handler

import (
	"github.com/aws/aws-sdk-go/service/kms"
	"fmt"
	"github.com/NSmithUK/local-kms-go/src/service"
)

func (r *RequestHandler) Decrypt() Response {

	var body *kms.DecryptInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.DecryptInput{}
	}

	//--------------------------------
	// Validation

	if len(body.CiphertextBlob) == 0 {
		msg := "CiphertextBlob is a required parameter"

		r.logger.Warnf(msg)
		return NewMissingParameterResponse(msg)
	}

	if len(body.CiphertextBlob) > 6144 {
		msg := fmt.Sprintf("1 validation error detected: Value '%s' at 'CiphertextBlob' failed to satisfy " +
			"constraint: Member must have length minimum length of 1 and maximum length of 6144.", string(body.CiphertextBlob))

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg)
	}
	
	//--------------------------------

	keyArn, keyVersion, ciphertext := service.DeconstructCipherResponse(body.CiphertextBlob)

	//--------------------------------

	key, _ := r.database.LoadKey(keyArn)

	if key == nil {
		msg := fmt.Sprintf("Key '%s' does not exist", keyArn)

		r.logger.Warnf(msg)
		return NewNotFoundExceptionResponse("The related key for this CiphertextBlob cannot be found")
	}

	//----------------------------------

	if key.Metadata.DeletionDate != 0 {
		// Key is pending deletion; cannot create alias
		msg := fmt.Sprintf("%s is pending deletion.", keyArn)

		r.logger.Warnf(msg)
		return NewKMSInvalidStateExceptionResponse(msg)
	}

	if !key.Metadata.Enabled {
		// Key is pending deletion; cannot create alias
		msg := fmt.Sprintf("%s is disabled.", keyArn)

		r.logger.Warnf(msg)
		return NewDisabledExceptionResponse(msg)
	}

	//--------------------------------

	// TODO - validate that a data key exists before accessing.

	dataKey := key.BackingKeys[keyVersion]

	plaintext, err := service.Decrypt(dataKey, ciphertext)

	if err != nil {
		msg := fmt.Sprintf("Unable to decode Ciphertext")

		r.logger.Warnf(msg)
		return NewInvalidCiphertextExceptionResponse(msg)
	}

	//--------------------------------

	response := &struct {
		KeyId			string
		Plaintext		[]byte
	}{
		KeyId: key.Metadata.Arn,
		Plaintext: plaintext,
	}

	return NewResponse( 200, response)
}