package kms

import (
	"context"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
)

func (k KmsService) ListKeyPolicies(ctx context.Context, req awskms.ListKeyPoliciesInput) (*awskms.ListKeyPoliciesOutput, []error) {
	// TODO
	return nil, nil
}
