package kms

import (
	"context"
	"log/slog"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
)

func (k KmsService) ReEncrypt(ctx context.Context, req awskms.ReEncryptInput) (*awskms.ReEncryptOutput, []error) {

	slog.Info("ReEncrypt will call Decrypt, then Encrypt")

	decrypt, errs := k.Decrypt(ctx, awskms.DecryptInput{
		CiphertextBlob: req.CiphertextBlob,

		KeyId:               req.SourceKeyId,
		EncryptionAlgorithm: req.SourceEncryptionAlgorithm,
		EncryptionContext:   req.SourceEncryptionContext,
	})

	if errs != nil {
		return nil, errs
	}

	encrypt, errs := k.Encrypt(ctx, awskms.EncryptInput{
		Plaintext:           decrypt.Plaintext,
		KeyId:               req.DestinationKeyId,
		EncryptionAlgorithm: req.DestinationEncryptionAlgorithm,
		EncryptionContext:   req.DestinationEncryptionContext,
	})

	if errs != nil {
		return nil, errs
	}

	//---

	sourceKeyId, err := k.ResolveKeyArn(req.SourceKeyId)
	if err != nil {
		return nil, []error{err}
	}
	sourceKey, err := k.Db.LoadKey(sourceKeyId)
	if err != nil {
		return nil, []error{err}
	}

	destinationKeyId, err := k.ResolveKeyArn(req.DestinationKeyId)
	if err != nil {
		return nil, []error{err}
	}
	destinationKey, err := k.Db.LoadKey(destinationKeyId)
	if err != nil {
		return nil, []error{err}
	}

	return &awskms.ReEncryptOutput{
		CiphertextBlob: encrypt.CiphertextBlob,

		KeyId:                          destinationKey.GetMetadata().KeyId,
		DestinationEncryptionAlgorithm: req.DestinationEncryptionAlgorithm,
		DestinationKeyMaterialId:       destinationKey.GetMetadata().CurrentKeyMaterialId,

		SourceKeyId:               sourceKey.GetMetadata().KeyId,
		SourceEncryptionAlgorithm: req.SourceEncryptionAlgorithm,
		SourceKeyMaterialId:       sourceKey.GetMetadata().CurrentKeyMaterialId,
	}, nil
}
