package kms

import (
	"context"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
)

func (k KmsService) GetKeyPolicy(ctx context.Context, req awskms.GetKeyPolicyInput) (*awskms.GetKeyPolicyOutput, []error) {
	// TODO
	return nil, nil
}
