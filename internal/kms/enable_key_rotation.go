package kms

import (
	"context"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
)

func (k KmsService) EnableKeyRotation(ctx context.Context, req awskms.EnableKeyRotationInput) (*awskms.EnableKeyRotationOutput, []error) {
	// TODO
	return nil, nil
}
