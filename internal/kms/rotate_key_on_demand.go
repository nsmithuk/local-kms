package kms

import (
	"context"
	"log/slog"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
)

func (k KmsService) RotateKeyOnDemand(ctx context.Context, req awskms.RotateKeyOnDemandInput) (*awskms.RotateKeyOnDemandOutput, []error) {

	key, err := k.getUsableKey(req.KeyId)
	if err != nil {
		return nil, []error{err}
	}

	err = key.RotateKeyOnDemand()
	if err != nil {
		return nil, []error{err}
	}

	//---

	err = k.Db.SaveKey(key)
	if err != nil {
		return nil, []error{err}
	}

	//---

	keyId := key.GetArn()

	slog.Info("RotateKeyOnDemand Success",
		"KeyId", *key.GetMetadata().KeyId,
	)

	//---

	return &awskms.RotateKeyOnDemandOutput{
		KeyId: &keyId,
	}, nil
}
