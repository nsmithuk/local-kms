package kms

import (
	"context"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
)

func (k KmsService) UpdateAlias(ctx context.Context, req awskms.UpdateAliasInput) (*awskms.UpdateAliasOutput, []error) {
	// TODO
	return nil, nil
}
