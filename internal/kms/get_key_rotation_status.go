package kms

import (
	"context"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
)

func (k KmsService) GetKeyRotationStatus(ctx context.Context, req awskms.GetKeyRotationStatusInput) (*awskms.GetKeyRotationStatusOutput, []error) {
	// TODO
	return nil, nil
}
