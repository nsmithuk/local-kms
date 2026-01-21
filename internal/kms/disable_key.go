package kms

import (
	"context"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
)

func (k KmsService) DisableKey(ctx context.Context, req awskms.CancelKeyDeletionInput) (*awskms.CancelKeyDeletionOutput, []error) {
	// TODO
	return nil, nil
}
