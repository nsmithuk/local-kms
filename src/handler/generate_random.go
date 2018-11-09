package handler

import (
	"github.com/aws/aws-sdk-go/service/kms"
	"fmt"
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
		msg := "NumberOfBytes is a required parameter"

		r.logger.Warnf(msg)
		return NewMissingParameterResponse(msg)
	}

	if *body.NumberOfBytes < 1 || *body.NumberOfBytes > 1024 {
		msg := fmt.Sprintf("1 validation error detected: Value '%d' at 'NumberOfBytes' failed to satisfy " +
			"constraint: Member must have minimum value of 1 and maximum value of 1024.", *body.NumberOfBytes)

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg)
	}

	//--------------------------------

	data := service.GenerateRandomData(uint16(*body.NumberOfBytes))

	//---

	//---

	r.logger.Infof("Random data generated: %d bytes\n", *body.NumberOfBytes)

	return NewResponse( 200, &struct {
		Plaintext	[]byte
	}{
		Plaintext: data,
	})

}
