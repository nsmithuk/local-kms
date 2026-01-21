package kms

import (
	"context"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
)

func (k KmsService) UpdateKeyDescription(ctx context.Context, req awskms.UpdateKeyDescriptionInput) (*awskms.UpdateKeyDescriptionOutput, []error) {
	// TODO
	return nil, nil
}
