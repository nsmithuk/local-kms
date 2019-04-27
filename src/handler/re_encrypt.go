package handler

import (
	"github.com/aws/aws-sdk-go/service/kms"
	"fmt"
	"github.com/nsmithuk/local-kms/src/service"
)

func (r *RequestHandler) ReEncrypt() Response {

	var body *kms.ReEncryptInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.ReEncryptInput{}
	}

	//--------------------------------
	// Validation

	if body.DestinationKeyId == nil {
		msg := "DestinationKeyId is a required parameter"

		r.logger.Warnf(msg)
		return NewMissingParameterResponse(msg)
	}

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
	// Decrypt

	keyArn, keySourceVersion, ciphertext, _ := service.DeconstructCipherResponse(body.CiphertextBlob)

	keySource, response := r.getUsableKey(keyArn)

	// If the response is not empty, there was an error
	if !response.Empty() {
		return response
	}

	//---

	if keySourceVersion >= uint32(len(keySource.BackingKeys)) {
		msg := "Required version of backing key is missing"

		r.logger.Warnf(msg)
		return NewInternalFailureExceptionResponse(msg)
	}

	//---

	dataKey := keySource.BackingKeys[keySourceVersion]

	plaintext, err := service.Decrypt(dataKey, ciphertext, body.SourceEncryptionContext)

	if err != nil {
		msg := "Unable to decode Ciphertext"

		r.logger.Warnf(msg)
		return NewInvalidCiphertextExceptionResponse(msg)
	}

	//--------------------------------
	// Encrypt

	keyDestination, response := r.getUsableKey(*body.DestinationKeyId)

	// If the response is not empty, there was an error
	if !response.Empty() {
		return response
	}

	//---

	keyDestinationVersion := len(keyDestination.BackingKeys) - 1

	dataKey = keyDestination.BackingKeys[keyDestinationVersion]

	ciphertext, _ = service.Encrypt(dataKey, plaintext, body.DestinationEncryptionContext)

	cipherResponse := service.ConstructCipherResponse(keyDestination.Metadata.Arn, uint32(keyDestinationVersion), ciphertext)

	//---

	r.logger.Infof("ReEncrypt called: %s -> %s\n", keySource.Metadata.Arn, keyDestination.Metadata.Arn)

	return NewResponse( 200, &struct {
		KeyId			string
		SourceKeyId		string
		CiphertextBlob	[]byte
	}{
		KeyId: keyDestination.Metadata.Arn,
		SourceKeyId: keySource.Metadata.Arn,
		CiphertextBlob: cipherResponse,
	})
}
