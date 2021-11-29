package handler

import (
	"fmt"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/nsmithuk/local-kms/src/cmk"
)

func (r *RequestHandler) Sign() Response {

	var body *kms.SignInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.SignInput{}
	}

	//--------------------------------
	// Validation

	if body.KeyId == nil {
		msg := "1 validation error detected: Value null at 'keyId' failed to satisfy constraint: Member must not be null"

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg)
	}

	if body.Message == nil {
		msg := "1 validation error detected: Value null at 'Message' failed to satisfy constraint: Member must not be null"

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg)
	}

	if len(body.Message) > 4096 {
		msg := fmt.Sprintf("1 validation error detected: Value '%s' at 'Message' failed to satisfy "+
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
		msg := fmt.Sprintf("1 validation error detected: Value '%s' at 'messageType' failed to satisfy "+
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
	case *cmk.RsaKey:

		if k.GetMetadata().KeyUsage == cmk.UsageEncryptDecrypt {
			msg := fmt.Sprintf("%s key usage is ENCRYPT_DECRYPT which is not valid for signing.", k.GetArn())
			r.logger.Warnf(msg)
			return NewInvalidKeyUsageException(msg)
		}

		signingKey = k
	case *cmk.EccKey:

		if k.GetMetadata().KeyUsage == cmk.UsageEncryptDecrypt {
			msg := fmt.Sprintf("%s key usage is ENCRYPT_DECRYPT which is not valid for signing.", k.GetArn())
			r.logger.Warnf(msg)
			return NewInvalidKeyUsageException(msg)
		}

		signingKey = k
	default:
		msg := fmt.Sprintf("%s key usage is ENCRYPT_DECRYPT which is not valid for Sign.", k.GetArn())
		r.logger.Warnf(msg)
		return NewInvalidKeyUsageException(msg)
	}

	//---

	var result []byte

	if *body.MessageType == "DIGEST" {
		result, err = signingKey.Sign(body.Message, cmk.SigningAlgorithm(*body.SigningAlgorithm))
	} else {
		result, err = signingKey.HashAndSign(body.Message, cmk.SigningAlgorithm(*body.SigningAlgorithm))
	}

	if err != nil {

		if _, ok := err.(*cmk.InvalidSigningAlgorithm); ok {
			msg := fmt.Sprintf("Algorithm %s is incompatible with key spec %s.", *body.SigningAlgorithm, key.GetMetadata().CustomerMasterKeySpec)

			r.logger.Warnf(msg)
			return NewInvalidKeyUsageException(msg)
		}

		if _, ok := err.(*cmk.InvalidDigestLength); ok {
			msg := fmt.Sprintf("Digest is invalid length for algorithm %s.", *body.SigningAlgorithm)

			r.logger.Warnf(msg)
			return NewValidationExceptionResponse(msg)
		}

		r.logger.Error(err.Error())
		return NewInvalidKeyUsageException(err.Error())
	}

	//---

	r.logger.Infof("%s message signed with %s, using key %s\n", *body.MessageType, signingKey.GetMetadata().CustomerMasterKeySpec, key.GetArn())

	return NewResponse(200, &struct {
		KeyId            string
		Signature        []byte
		SigningAlgorithm cmk.SigningAlgorithm
	}{
		KeyId:            key.GetArn(),
		Signature:        result,
		SigningAlgorithm: cmk.SigningAlgorithm(*body.SigningAlgorithm),
	})
}
