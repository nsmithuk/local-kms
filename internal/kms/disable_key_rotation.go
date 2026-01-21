package kms

import (
	"context"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
)

func (k KmsService) DisableKeyRotation(ctx context.Context, req awskms.DisableKeyRotationInput) (*awskms.DisableKeyRotationOutput, []error) {
	// TODO
	return nil, nil
}
