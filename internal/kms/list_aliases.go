package kms

import (
	"context"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
)

func (k KmsService) ListAliases(ctx context.Context, req awskms.ListAliasesInput) (*awskms.ListAliasesOutput, []error) {
	// TODO
	return nil, nil
}
