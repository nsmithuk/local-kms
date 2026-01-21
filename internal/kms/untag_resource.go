package kms

import (
	"context"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
)

func (k KmsService) UntagResource(ctx context.Context, req awskms.UntagResourceInput) (*awskms.UntagResourceOutput, []error) {
	// TODO
	return nil, nil
}
