package kms

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
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

	return &awskms.RotateKeyOnDemandOutput{
		KeyId: aws.String(key.GetId()),
	}, nil
}
