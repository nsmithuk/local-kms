package kms

import (
	"context"
	"errors"
	"log/slog"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/nsmithuk/local-kms/internal/kms/cmk"
	"github.com/nsmithuk/local-kms/internal/kms/data"
	"github.com/nsmithuk/local-kms/internal/kms/kmserr"
)

func (k KmsService) GetPublicKey(ctx context.Context, req awskms.GetPublicKeyInput) (*awskms.GetPublicKeyOutput, []error) {

	keyId, err := k.ResolveKeyArn(req.KeyId)
	if err != nil {
		return nil, []error{err}
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

	public, err := key.GetPublicKey()
	if err != nil {
		if errors.Is(err, cmk.ErrOperationNotSupported) {
			return nil, []error{
				kmserr.NewValidation(kmserr.CauseUnsupportedOperationException, "GetPublicKey not supported with KeySpec %s", metadata.KeySpec),
			}
		}
		return nil, []error{err}
	}

	//---

	slog.Info("GetPubicKey Success",
		"KeyId", *metadata.KeyId,
		"KeySpec", metadata.KeySpec,
		"KeyUsage", metadata.KeyUsage,
		"SigningAlgorithms", metadata.SigningAlgorithms,
		"KeyAgreementAlgorithms", metadata.KeyAgreementAlgorithms,
	)

	//---

	return &awskms.GetPublicKeyOutput{
		PublicKey:              public,
		CustomerMasterKeySpec:  metadata.CustomerMasterKeySpec,
		EncryptionAlgorithms:   metadata.EncryptionAlgorithms,
		KeyAgreementAlgorithms: metadata.KeyAgreementAlgorithms,
		KeyId:                  metadata.KeyId,
		KeySpec:                metadata.KeySpec,
		KeyUsage:               metadata.KeyUsage,
		SigningAlgorithms:      metadata.SigningAlgorithms,
	}, nil
}
