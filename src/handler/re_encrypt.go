package handler

import (
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/nsmithuk/local-kms/src/cmk"
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

		r.logger.Warn(msg)
		return NewMissingParameterResponse(msg)
	}

	if len(body.CiphertextBlob) == 0 {
		msg := "CiphertextBlob is a required parameter"

		r.logger.Warn(msg)
		return NewMissingParameterResponse(msg)
	}

	if len(body.CiphertextBlob) > 6144 {
		msg := fmt.Sprintf("1 validation error detected: Value '%s' at 'CiphertextBlob' failed to satisfy "+
			"constraint: Member must have length minimum length of 1 and maximum length of 6144.", string(body.CiphertextBlob))

		r.logger.Warn(msg)
		return NewValidationExceptionResponse(msg)
	}

	if body.SourceEncryptionAlgorithm == "" {
		body.SourceEncryptionAlgorithm = "SYMMETRIC_DEFAULT"
	}

	if body.DestinationEncryptionAlgorithm == "" {
		body.DestinationEncryptionAlgorithm = "SYMMETRIC_DEFAULT"
	}

	sourceEncryptionContext := make(map[string]*string, len(body.SourceEncryptionContext))
	for k, v := range body.SourceEncryptionContext {
		value := v
		sourceEncryptionContext[k] = &value
	}

	destinationEncryptionContext := make(map[string]*string, len(body.DestinationEncryptionContext))
	for k, v := range body.DestinationEncryptionContext {
		value := v
		destinationEncryptionContext[k] = &value
	}

	//--------------------------------
	// Decrypt

	keyArn, keySourceVersion, ciphertext, _ := service.UnpackCiphertextBlob(body.CiphertextBlob)

	keySource, response := r.getUsableKey(keyArn)

	// If the response is not empty, there was an error
	if !response.Empty() {
		return response
	}

	//---

	var plaintext []byte

	switch k := keySource.(type) {
	case *cmk.AesKey:

		plaintext, err = k.Decrypt(keySourceVersion, ciphertext, sourceEncryptionContext)
		if err != nil {
			msg := fmt.Sprintf("Unable to decode Ciphertext: %s", err)
			r.logger.Warn(msg)

			return NewInvalidCiphertextExceptionResponse("")
		}

	default:
		return NewInternalFailureExceptionResponse("key type not yet supported for encryption")
	}

	//--------------------------------
	// Encrypt

	keyDestination, response := r.getUsableKey(*body.DestinationKeyId)

	// If the response is not empty, there was an error
	if !response.Empty() {
		return response
	}

	//---

	var cipherResponse []byte

	switch k := keyDestination.(type) {
	case *cmk.AesKey:

		cipherResponse, err = k.EncryptAndPackage(plaintext, destinationEncryptionContext)
		if err != nil {
			r.logger.Error(err.Error())
			return NewInternalFailureExceptionResponse(err.Error())
		}

	default:
		return NewInternalFailureExceptionResponse("key type not yet supported for encryption")
	}

	//---

	r.logger.Infof("ReEncrypt called: %s -> %s\n", keySource.GetArn(), keyDestination.GetArn())

	return NewResponse(200, &struct {
		KeyId                          string
		SourceKeyId                    string
		CiphertextBlob                 []byte
		SourceEncryptionAlgorithm      cmk.EncryptionAlgorithm
		DestinationEncryptionAlgorithm cmk.EncryptionAlgorithm
	}{
		KeyId:                          keyDestination.GetArn(),
		SourceKeyId:                    keySource.GetArn(),
		CiphertextBlob:                 cipherResponse,
		SourceEncryptionAlgorithm:      cmk.EncryptionAlgorithm(body.SourceEncryptionAlgorithm),
		DestinationEncryptionAlgorithm: cmk.EncryptionAlgorithm(body.DestinationEncryptionAlgorithm),
	})
}
