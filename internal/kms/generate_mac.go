package kms

import (
	"context"
	"errors"
	"log/slog"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/nsmithuk/local-kms/internal/kms/data"
	"github.com/nsmithuk/local-kms/internal/kms/kmserr"
	"github.com/nsmithuk/local-kms/internal/kms/validation"
)

func (k KmsService) GenerateMac(ctx context.Context, req awskms.GenerateMacInput) (*awskms.GenerateMacOutput, []error) {

	validator := validation.Validator{}
	validationErrors := make([]error, 0)

	keyId, err := k.ResolveKeyArn(req.KeyId)
	if err != nil {
		validationErrors = append(validationErrors, err)
	}

	if err = validator.RequiredPointer(req.Message, "Message"); err != nil {
		validationErrors = append(validationErrors, err)
	} else if err = validator.ByteLength(req.Message, "Message", 4096); err != nil {
		validationErrors = append(validationErrors, err)
	}

	// We'll validate the actual signing algorithm at the key cmk level.
	if err = validator.RequiredString(string(req.MacAlgorithm), "MacAlgorithm"); err != nil {
		validationErrors = append(validationErrors, err)
	}

	if len(validationErrors) > 0 {
		return nil, validationErrors
	}

	// ---

	key, err := k.Db.LoadKey(keyId)
	if err != nil {
		if errors.Is(err, data.ErrKeyNotFound) {
			return nil, []error{
				kmserr.NewValidation(kmserr.CauseNotFoundException, "A key with the arn %s does not exists", keyId),
			}
		}
		return nil, []error{err}
	}

	//---

	mac, err := key.GenerateMac(req.Message, req.MacAlgorithm)
	if err != nil {
		return nil, []error{err}
	}

	//---

	metadata := key.GetMetadata()

	slog.Info("GenerateMac Success",
		"KeyId", *metadata.KeyId,
		"MacAlgorithm", req.MacAlgorithm,
		"Mac", mac,
	)

	//---

	return &awskms.GenerateMacOutput{
		KeyId:        &keyId,
		MacAlgorithm: req.MacAlgorithm,
		Mac:          mac,
	}, nil

}
