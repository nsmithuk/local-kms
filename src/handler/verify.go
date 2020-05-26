package handler

import (
	"fmt"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/nsmithuk/local-kms/src/cmk"
)

func (r *RequestHandler) Verify() Response {

	var body *kms.VerifyInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.VerifyInput{}
	}

	//--------------------------------
	// Validation

	if body.KeyId == nil {
		msg := "1 validation error detected: Value null at 'keyId' failed to satisfy constraint: Member must not be null"

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg)
	}

	if body.Signature == nil {
		msg := "1 validation error detected: Value null at 'Signature' failed to satisfy constraint: Member must not be null"

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg)
	}

	if body.Message == nil {
		msg := "1 validation error detected: Value null at 'Message' failed to satisfy constraint: Member must not be null"

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg)
	}

	if len(body.Message) > 4096 {
		msg := fmt.Sprintf("1 validation error detected: Value '%s' at 'Message' failed to satisfy " +
			"constraint: Member must have minimum length of 1 and maximum length of 4096.", string(body.Message))

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg)
	}

	if body.SigningAlgorithm == nil {
		msg := "1 validation error detected: Value null at 'SigningAlgorithm' failed to satisfy constraint: Member must not be null"

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg)
	}

	if body.MessageType == nil {
		d := "RAW"
		body.MessageType = &d
	}

	if !(*body.MessageType == "RAW" || *body.MessageType == "DIGEST") {
		msg := fmt.Sprintf("1 validation error detected: Value '%s' at 'messageType' failed to satisfy " +
			"constraint: Member must satisfy enum value set: [DIGEST, RAW]", *body.MessageType)

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg)
	}

	//----------------------------------

	key, response := r.getUsableKey(*body.KeyId)

	// If the response is not empty, there was an error
	if !response.Empty() {
		return response
	}

	var signingKey cmk.SigningKey

	switch k := key.(type) {
	case *cmk.EccKey:

		if k.GetMetadata().KeyUsage == cmk.UsageEncryptDecrypt {
			msg := fmt.Sprintf("%s key usage is ENCRYPT_DECRYPT which is not valid for signing.", k.GetArn())

			r.logger.Warnf(msg)
			return NewInvalidKeyUsageException(msg)
		}

		signingKey = k
	default:
		msg := fmt.Sprintf("%s key usage is ENCRYPT_DECRYPT which is not valid for Verify.", k.GetArn())
		r.logger.Warnf(msg)
		return NewInvalidKeyUsageException(msg)
	}

	//---

	var valid bool

	if *body.MessageType == "DIGEST" {
		valid, err = signingKey.Verify(body.Signature, body.Message)
	} else {
		valid, err = signingKey.HashAndVerify(body.Signature, body.Message, cmk.SigningAlgorithm(*body.SigningAlgorithm))
	}

	if err != nil {
		r.logger.Error(err.Error())
		return NewInvalidKeyUsageException(err.Error())
	}

	//---

	r.logger.Infof("%s message verification %t with %s, using key %s\n", *body.MessageType, valid, *body.SigningAlgorithm, key.GetArn())

	if !valid {
		return NewKMSInvalidSignatureException("")
	}

	return NewResponse( 200, &struct {
		KeyId				string
		SignatureValid		bool
		SigningAlgorithm	cmk.SigningAlgorithm
	}{
		KeyId: key.GetArn(),
		SignatureValid: valid,
		SigningAlgorithm: cmk.SigningAlgorithm(*body.SigningAlgorithm),
	})
}
