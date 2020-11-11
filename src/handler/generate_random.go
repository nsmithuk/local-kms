package handler

import (
	"fmt"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/nsmithuk/local-kms/src/service"
)

func (r *RequestHandler) GenerateRandom() Response {

	var body *kms.GenerateRandomInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.GenerateRandomInput{}
	}

	//--------------------------------
	// Validation

	if body.NumberOfBytes == nil {
		msg := "Please specify either number of bytes or key spec."

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg)
	}

	if *body.NumberOfBytes < 1 {
		msg := fmt.Sprintf("1 validation error detected: Value '%d' at 'numberOfBytes' failed to satisfy "+
			"constraint: Member must have value greater than or equal to 1", *body.NumberOfBytes)

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg)
	}

	if *body.NumberOfBytes > 1024 {
		msg := fmt.Sprintf("1 validation error detected: Value '%d' at 'numberOfBytes' failed to satisfy "+
			"constraint: Member must have value less than or equal to 1024", *body.NumberOfBytes)

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg)
	}

	//--------------------------------

	data := service.GenerateRandomData(uint16(*body.NumberOfBytes))

	//---

	r.logger.Infof("Random data generated: %d bytes\n", len(data))

	return NewResponse(200, &struct {
		Plaintext []byte
	}{
		Plaintext: data,
	})

}
