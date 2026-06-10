package handler

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/nsmithuk/local-kms/src/cmk"
)

func (r *RequestHandler) VerifyMac() Response {

	var body *kms.VerifyMacInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.VerifyMacInput{}
	}

	//---

	if body.KeyId == nil {
		msg := "1 validation error detected: Value null at 'keyId' failed to satisfy constraint: Member must not be null"
		r.logger.Warn(msg)
		return NewValidationExceptionResponse(msg)
	}

	if body.Message == nil {
		msg := "1 validation error detected: Value null at 'message' failed to satisfy constraint: Member must not be null"
		r.logger.Warn(msg)
		return NewValidationExceptionResponse(msg)
	}

	if body.Mac == nil {
		msg := "1 validation error detected: Value null at 'mac' failed to satisfy constraint: Member must not be null"
		r.logger.Warn(msg)
		return NewValidationExceptionResponse(msg)
	}

	if body.MacAlgorithm == "" {
		msg := "1 validation error detected: Value null at 'macAlgorithm' failed to satisfy constraint: Member must not be null"
		r.logger.Warn(msg)
		return NewValidationExceptionResponse(msg)
	}

	//--------------------------------
	// Get the key

	key, response := r.getUsableKey(*body.KeyId)
	if !response.Empty() {
		return response
	}

	//---

	if key.GetMetadata().KeyState != cmk.KeyStateEnabled {
		return NewDisabledExceptionResponse("")
	}

	if key.GetKeyType() != cmk.TypeHmac {
		msg := fmt.Sprintf("The key usage %s is not valid for this operation.", key.GetMetadata().KeyUsage)
		r.logger.Warn(msg)
		return NewValidationExceptionResponse(msg)
	}

	//---

	// Validate the MAC algorithm is supported by this key
	supportedAlgorithms := key.GetMetadata().SigningAlgorithms
	algorithmSupported := false
	for _, alg := range supportedAlgorithms {
		if string(alg) == string(body.MacAlgorithm) {
			algorithmSupported = true
			break
		}
	}

	if !algorithmSupported {
		msg := fmt.Sprintf("The request is not valid for the key spec %s.", key.GetMetadata().KeySpec)
		r.logger.Warn(msg)
		return NewValidationExceptionResponse(msg)
	}

	//---

	macKey, ok := key.(cmk.MacKey)
	if !ok {
		msg := "Key does not support MAC operations"
		r.logger.Warn(msg)
		return NewValidationExceptionResponse(msg)
	}

	//---

	macValid, err := macKey.VerifyMac(body.Message, body.Mac, cmk.SigningAlgorithm(body.MacAlgorithm))
	if err != nil {
		r.logger.Error(err)
		return NewInternalFailureExceptionResponse(err.Error())
	}

	//---

	keyArn := key.GetArn()
	r.logger.Infof("MAC verification performed using key %s with algorithm %s, result: %v", keyArn, body.MacAlgorithm, macValid)

	return NewResponse(200, &kms.VerifyMacOutput{
		KeyId:        &keyArn,
		MacValid:     macValid,
		MacAlgorithm: body.MacAlgorithm,
	})
}
