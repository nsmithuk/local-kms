package kms

import (
	"context"
	"errors"
	"log/slog"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	awskmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/nsmithuk/local-kms/internal/kms/cmk"
	"github.com/nsmithuk/local-kms/internal/kms/data"
	"github.com/nsmithuk/local-kms/internal/kms/kmserr"
	"github.com/nsmithuk/local-kms/internal/kms/validation"
)

func (k KmsService) Sign(ctx context.Context, req awskms.SignInput) (*awskms.SignOutput, []error) {

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

	if err = validator.RequiredString(string(req.SigningAlgorithm), "SigningAlgorithm"); err != nil {
		validationErrors = append(validationErrors, err)
	}

	messageType := req.MessageType
	if messageType == "" {
		messageType = awskmstypes.MessageTypeRaw
	}
	if err = validator.MessageType(messageType); err != nil {
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

	metadata := key.GetMetadata()

	signature, err := key.Sign(req.Message, req.SigningAlgorithm, messageType)
	if err != nil {
		if errors.Is(err, cmk.ErrOperationNotSupported) {
			return nil, []error{
				kmserr.NewValidation(kmserr.CauseUnsupportedOperationException, "Sign not supported with KeySpec %s", metadata.KeySpec),
			}
		}
		return nil, []error{err}
	}

	//---

	slog.Info("Sign Success",
		"KeyId", *metadata.KeyId,
		"KeySpec", metadata.KeySpec,
		"KeyUsage", metadata.KeyUsage,
		"SigningAlgorithms", metadata.SigningAlgorithms,
		"MessageType", messageType,
	)

	//---

	return &awskms.SignOutput{
		KeyId:            &keyId,
		Signature:        signature,
		SigningAlgorithm: req.SigningAlgorithm,
	}, nil
}
