package kms

import (
	"context"
	"log/slog"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/nsmithuk/local-kms/internal/kms/kmserr"
	"github.com/nsmithuk/local-kms/internal/kms/validation"
)

func (k KmsService) VerifyMac(ctx context.Context, req awskms.VerifyMacInput) (*awskms.VerifyMacOutput, []error) {

	key, err := k.getUsableKey(req.KeyId)
	if err != nil {
		return nil, []error{err}
	}

	validator := validation.Validator{}
	validationErrors := make([]error, 0)

	if err = validator.RequiredPointer(req.Message, "Message"); err != nil {
		validationErrors = append(validationErrors, err)
	} else if err = validator.ByteLength(req.Message, "Message", 4096); err != nil {
		validationErrors = append(validationErrors, err)
	}

	if err = validator.RequiredString(string(req.MacAlgorithm), "MacAlgorithm"); err != nil {
		validationErrors = append(validationErrors, err)
	}

	if err = validator.RequiredPointer(req.Mac, "Mac"); err != nil {
		validationErrors = append(validationErrors, err)
	}

	if len(validationErrors) > 0 {
		return nil, validationErrors
	}

	keyId := key.GetArn()

	//---

	valid, err := key.VerifyMac(req.Message, req.MacAlgorithm, req.Mac)
	if err != nil {
		return nil, []error{err}
	}

	if !valid {
		return nil, []error{
			kmserr.NewValidation(kmserr.CauseKMSInvalidMacException, "MAC verification failed"),
		}
	}

	//---

	metadata := key.GetMetadata()

	slog.Info("VerifyMac Success",
		"KeyId", *metadata.KeyId,
		"MacAlgorithm", req.MacAlgorithm,
	)

	//---

	return &awskms.VerifyMacOutput{
		KeyId:        &keyId,
		MacAlgorithm: req.MacAlgorithm,
		MacValid:     true,
	}, nil

}
