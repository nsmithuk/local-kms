package kms

import (
	"context"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
)

func (k KmsService) EnableKey(ctx context.Context, req awskms.EnableKeyInput) (*awskms.EnableKeyOutput, []error) {
	// TODO
	return nil, nil
}
