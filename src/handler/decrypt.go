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
		_, ok := err.(base64.CorruptInputError); if ok {
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
		msg := fmt.Sprintf("1 validation error detected: Value '%s' at 'CiphertextBlob' failed to satisfy " +
			"constraint: Member must have length minimum length of 1 and maximum length of 6144.", string(body.CiphertextBlob))

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg)
	}

	//--------------------------------

	keyArn, keyVersion, ciphertext, ok := service.UnpackCiphertextBlob(body.CiphertextBlob)

	// If we unable to deconstruct the message
	if !ok {
		r.logger.Warnf("Unable to deconstruct ciphertext")
		return NewInvalidCiphertextExceptionResponse("")
	}

	key, response := r.getUsableKey(keyArn)

	// If the response is not empty, there was an error
	if !response.Empty() {

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

	default:
		return NewInternalFailureExceptionResponse("key type not yet supported for encryption")
	}

	//--------------------------------

	r.logger.Infof("Decryption called: %s\n", key.GetArn())

	return NewResponse( 200, &struct {
		KeyId			string
		Plaintext		[]byte
	}{
		KeyId: key.GetArn(),
		Plaintext: plaintext,
	})
}