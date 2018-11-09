package handler

import (
	"github.com/aws/aws-sdk-go/service/kms"
	"fmt"
	"github.com/nsmithuk/local-kms/src/service"
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

	key, response := r.getUsableKey(keyArn)

	// If the response is not empty, there was an error
	if !response.Empty() {
		return response
	}

	//--------------------------------

	if keyVersion >= uint32(len(key.BackingKeys)) {
		msg := "Required version of backing key is missing"

		r.logger.Warnf(msg)
		return NewInternalFailureExceptionResponse(msg)
	}

	//---

	dataKey := key.BackingKeys[keyVersion]

	plaintext, err := service.Decrypt(dataKey, ciphertext)

	if err != nil {
		msg := "Unable to decode Ciphertext"

		r.logger.Warnf(msg)
		return NewInvalidCiphertextExceptionResponse(msg)
	}

	//--------------------------------

	r.logger.Infof("Decryption called: %s\n", key.Metadata.Arn)

	return NewResponse( 200, &struct {
		KeyId			string
		Plaintext		[]byte
	}{
		KeyId: key.Metadata.Arn,
		Plaintext: plaintext,
	})
}