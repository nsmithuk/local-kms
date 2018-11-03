package handler

import (
	"github.com/aws/aws-sdk-go/service/kms"
	"fmt"
	"github.com/NSmithUK/local-kms-go/src/service"
)

type GenerateDataKeyResponse struct {
	KeyId			string
	Plaintext		[]byte	`json:",omitempty"`
	CiphertextBlob	[]byte
}

//----------------------------------

func (r *RequestHandler) GenerateDataKey() Response {

	errResponse, keyResponse := r.generateDataKey()

	if !errResponse.Empty() {
		return errResponse
	}

	return NewResponse( 200, keyResponse)
}

//------------------------------------------------------------------------------------------
// Generate code shared between GenerateDataKey() and GenerateDataKeyWithoutPlaintext()

func (r *RequestHandler) generateDataKey() (Response, *GenerateDataKeyResponse) {

	var body *kms.GenerateDataKeyInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.GenerateDataKeyInput{}
	}

	var bytesRequired uint16

	//--------------------------------
	// Validation

	if body.KeyId == nil {
		msg := "KeyId is a required parameter"

		r.logger.Warnf(msg)
		return NewMissingParameterResponse(msg), nil
	}

	if body.NumberOfBytes == nil && body.KeySpec == nil {
		msg := "1 validation error detected: Either KeySpec or NumberOfBytes is required."

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg), nil
	}

	if body.NumberOfBytes != nil && body.KeySpec != nil {
		msg := "1 validation error detected: Both KeySpec and NumberOfBytes cannot be provided."

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg), nil
	}

	if body.NumberOfBytes != nil && (*body.NumberOfBytes < 1 || *body.NumberOfBytes > 1024) {
		msg := fmt.Sprintf("1 validation error detected: Value '%d' at 'NumberOfBytes' failed to satisfy " +
			"constraint: Member must have minimum value of 1 and maximum value of 1024.", *body.NumberOfBytes)

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg), nil
	}

	if body.KeySpec != nil {
		switch *body.KeySpec {
		case "AES_128":
			bytesRequired = 128 / 8

		case "AES_256":
			bytesRequired = 256 / 8

		default:
			msg := fmt.Sprintf("1 validation error detected: Value '%s' at 'KeySpec' failed to satisfy " +
				"constraint: Member must be AES_128 or AES_256", *body.KeySpec)

			r.logger.Warnf(msg)
			return NewValidationExceptionResponse(msg), nil
		}

	} else {
		bytesRequired = uint16(*body.NumberOfBytes)
	}

	//----------------------------------

	key, response := r.getUsableKey(*body.KeyId)

	// If the response is not empty, there was an error
	if !response.Empty() {
		return response, nil
	}

	//----------------------------------

	plaintext := service.GenerateRandomData(bytesRequired)

	keyVersion := len(key.BackingKeys) - 1

	dataKey := key.BackingKeys[keyVersion]

	ciphertext, err := service.Encrypt(dataKey, plaintext)

	cipherResponse := service.ConstructCipherResponse(key.Metadata.Arn, uint32(keyVersion), ciphertext)

	return Response{}, &GenerateDataKeyResponse {
		KeyId: key.Metadata.Arn,
		Plaintext: plaintext,
		CiphertextBlob: cipherResponse,
	}
}
