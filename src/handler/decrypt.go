package handler

import (
	"encoding/base64"
	"fmt"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/nsmithuk/local-kms/src/cmk"
	"github.com/nsmithuk/local-kms/src/service"
)

func (r *RequestHandler) Decrypt() Response {

	var body *kms.DecryptInput
	err := r.decodeBodyInto(&body)

	if err != nil {

		// Errors decoding the base64 have a specific error.
		_, ok := err.(base64.CorruptInputError)
		if ok {
			r.logger.Warnf("Unable to decode base64 value")
			return NewSerializationExceptionResponse("")
		}

		body = &kms.DecryptInput{}
	}

	//--------------------------------
	// Validation

	if len(body.CiphertextBlob) == 0 {
		msg := "1 validation error detected: Value at 'ciphertextBlob' failed to satisfy constraint: Member must " +
			"have length greater than or equal to 1"

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg)
	}

	if len(body.CiphertextBlob) > 6144 {
		msg := fmt.Sprintf("1 validation error detected: Value '%s' at 'CiphertextBlob' failed to satisfy "+
			"constraint: Member must have length minimum length of 1 and maximum length of 6144.", string(body.CiphertextBlob))

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg)
	}

	if body.EncryptionAlgorithm == nil {
		d := "SYMMETRIC_DEFAULT"
		body.EncryptionAlgorithm = &d
	}

	//--------------------------------

	// If a KeyId is provided, we always use that, even for symmetric keys.
	var key cmk.Key
	var response Response
	var keyVersion uint32

	// We default of the full CiphertextBlob
	// Replaced later in the case of AES payloads
	var ciphertext []byte = body.CiphertextBlob

	if body.KeyId != nil {
		key, response = r.getUsableKey(*body.KeyId)

		// If the response is not empty, there was an error
		if !response.Empty() {
			return response
		}
	}

	/*
		We need to unpack the payload if either:
		- We don't already have a valid key; or
		- We do have a valid key, and it's of type AES.
	*/
	if _, isAes := key.(*cmk.AesKey); key == nil || isAes {

		var keyArn string
		var ok bool

		keyArn, keyVersion, ciphertext, ok = service.UnpackCiphertextBlob(body.CiphertextBlob)

		// If we unable to deconstruct the message
		if !ok {
			r.logger.Warnf("Unable to deconstruct ciphertext")
			return NewInvalidCiphertextExceptionResponse("")
		}

		// We only use the unpacked keyArn if a key wasn't supplied.
		if key == nil {
			key, response = r.getUsableKey(keyArn)
		}
	}

	// If the response is not empty, there was an error
	if key == nil || !response.Empty() {

		// We override the returned error on decrypt. The message is more generic such that it doesn't leak any metadata.
		msg := "The ciphertext refers to a customer master key that does not exist, does not exist in this region, " +
			"or you are not allowed to access."

		return NewAccessDeniedExceptionResponse(msg)
	}

	//--------------------------------

	var plaintext []byte

	switch k := key.(type) {
	case *cmk.AesKey:

		plaintext, err = k.Decrypt(keyVersion, ciphertext, body.EncryptionContext)
		if err != nil {
			msg := fmt.Sprintf("Unable to decode Ciphertext: %s", err)
			r.logger.Warnf(msg)

			return NewInvalidCiphertextExceptionResponse("")
		}

	case *cmk.RsaKey:

		plaintext, err = k.Decrypt(ciphertext, cmk.EncryptionAlgorithm(*body.EncryptionAlgorithm))
		if err != nil {
			msg := fmt.Sprintf("Unable to decode Ciphertext: %s", err)
			r.logger.Warnf(msg)

			return NewInvalidCiphertextExceptionResponse("")
		}

	default:
		return NewInternalFailureExceptionResponse("key type not yet supported for decryption")
	}

	//--------------------------------

	r.logger.Infof("Decryption called: %s\n", key.GetArn())

	return NewResponse(200, &struct {
		KeyId               string
		Plaintext           []byte
		EncryptionAlgorithm cmk.EncryptionAlgorithm
	}{
		KeyId:               key.GetArn(),
		Plaintext:           plaintext,
		EncryptionAlgorithm: cmk.EncryptionAlgorithm(*body.EncryptionAlgorithm),
	})
}
