package kms

import (
	"context"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
)

func (k KmsService) PutKeyPolicy(ctx context.Context, req awskms.PutKeyPolicyInput) (*awskms.PutKeyPolicyOutput, []error) {
	// TODO
	return nil, nil
}
