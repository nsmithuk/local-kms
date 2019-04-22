package handler

import (
	"github.com/aws/aws-sdk-go/service/kms"
	"fmt"
	"github.com/nsmithuk/local-kms/src/service"
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
		msg := "1 validation error detected: Value at 'plaintext' failed to satisfy constraint: Member must have " +
			"length greater than or equal to 1"

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg)
	}

	if len(body.Plaintext) > 4096 {
		msg := fmt.Sprintf("1 validation error detected: Value '%s' at 'Plaintext' failed to satisfy " +
			"constraint: Member must have minimum length of 1 and maximum length of 4096.", string(body.Plaintext))

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg)
	}

	//----------------------------------

	key, response := r.getUsableKey(*body.KeyId)

	// If the response is not empty, there was an error
	if !response.Empty() {
		return response
	}

	//----------------------------------

	keyVersion := len(key.BackingKeys) - 1

	dataKey := key.BackingKeys[keyVersion]

	ciphertext, _ := service.Encrypt(dataKey, body.Plaintext)

	cipherResponse := service.ConstructCipherResponse(key.Metadata.Arn, uint32(keyVersion), ciphertext)

	//---

	r.logger.Infof("Encryption called: %s\n", key.Metadata.Arn)

	return NewResponse( 200, &struct {
		KeyId			string
		CiphertextBlob	[]byte
	}{
		KeyId: key.Metadata.Arn,
		CiphertextBlob: cipherResponse,
	})
}
