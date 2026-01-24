package kms

import (
	"context"
	"fmt"
	"log/slog"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/nsmithuk/local-kms/internal/kms/cmk"
	"github.com/nsmithuk/local-kms/internal/kms/validation"
)

func (k KmsService) GenerateRandom(ctx context.Context, req awskms.GenerateRandomInput) (*awskms.GenerateRandomOutput, []error) {

	validator := validation.Validator{}
	validationErrors := make([]error, 0)

	if err := validator.RequiredPointer(req.NumberOfBytes, "NumberOfBytes"); err != nil {
		validationErrors = append(validationErrors, err)
	}

	numberOfBytes := *req.NumberOfBytes

	if numberOfBytes < 1 {
		validationErrors = append(validationErrors, fmt.Errorf("1 validation error detected: Value '%d' at 'numberOfBytes' failed to satisfy "+
			"constraint: Member must have value greater than or equal to 1", numberOfBytes))
	}

	if numberOfBytes > 1024 {
		validationErrors = append(validationErrors, fmt.Errorf("1 validation error detected: Value '%d' at 'numberOfBytes' failed to satisfy "+
			"constraint: Member must have value less than or equal to 1024", numberOfBytes))
	}

	if len(validationErrors) > 0 {
		return nil, validationErrors
	}

	plaintext := cmk.GenerateRandomData(numberOfBytes)

	//---

	slog.Info("GenerateRandom Success",
		"Plaintext", plaintext,
	)

	//---

	return &awskms.GenerateRandomOutput{
		Plaintext: plaintext,
	}, nil

}
