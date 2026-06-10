package handler

import (
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/nsmithuk/local-kms/src/cmk"
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

		r.logger.Warn(msg)
		return NewMissingParameterResponse(msg)
	}

	if len(body.Plaintext) == 0 {
		msg := "1 validation error detected: Value at 'plaintext' failed to satisfy constraint: Member must have " +
			"length greater than or equal to 1"

		r.logger.Warn(msg)
		return NewValidationExceptionResponse(msg)
	}

	if len(body.Plaintext) > 4096 {
		msg := fmt.Sprintf("1 validation error detected: Value '%s' at 'Plaintext' failed to satisfy "+
			"constraint: Member must have minimum length of 1 and maximum length of 4096.", string(body.Plaintext))

		r.logger.Warn(msg)
		return NewValidationExceptionResponse(msg)
	}

	if body.EncryptionAlgorithm == "" {
		body.EncryptionAlgorithm = "SYMMETRIC_DEFAULT"
	}

	encryptionContext := make(map[string]*string, len(body.EncryptionContext))
	for k, v := range body.EncryptionContext {
		value := v
		encryptionContext[k] = &value
	}

	//----------------------------------

	key, response := r.getUsableKey(*body.KeyId)

	// If the response is not empty, there was an error
	if !response.Empty() {
		return response
	}

	//----------------------------------

	var cipherResponse []byte

	switch k := key.(type) {
	case *cmk.AesKey:

		cipherResponse, err = k.EncryptAndPackage(body.Plaintext, encryptionContext)
		if err != nil {
			r.logger.Error(err.Error())
			return NewInternalFailureExceptionResponse(err.Error())
		}

	case *cmk.RsaKey:

		if k.GetMetadata().KeyUsage != cmk.UsageEncryptDecrypt {
			msg := fmt.Sprintf("%s key usage is %s which is not valid for Encrypt.", k.GetArn(), k.GetMetadata().KeyUsage)
			r.logger.Warn(msg)
			return NewInvalidKeyUsageException(msg)
		}

		cipherResponse, err = k.Encrypt(body.Plaintext, cmk.EncryptionAlgorithm(body.EncryptionAlgorithm))
		if err != nil {
			r.logger.Error(err.Error())
			return NewInternalFailureExceptionResponse(err.Error())
		}

	default:

		if k.GetMetadata().KeyUsage == cmk.UsageSignVerify {
			msg := fmt.Sprintf("%s key usage is SIGN_VERIFY which is not valid for Encrypt.", k.GetArn())
			r.logger.Warn(msg)
			return NewInvalidKeyUsageException(msg)
		}

		return NewInternalFailureExceptionResponse("key type not yet supported for encryption")
	}

	//---

	r.logger.Infof("Encryption called: %s\n", key.GetArn())

	return NewResponse(200, &struct {
		KeyId               string
		CiphertextBlob      []byte
		EncryptionAlgorithm cmk.EncryptionAlgorithm
	}{
		KeyId:               key.GetArn(),
		CiphertextBlob:      cipherResponse,
		EncryptionAlgorithm: cmk.EncryptionAlgorithm(body.EncryptionAlgorithm),
	})
}
