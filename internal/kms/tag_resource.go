package kms

import (
	"context"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
)

func (k KmsService) TagResource(ctx context.Context, req awskms.TagResourceInput) (*awskms.TagResourceOutput, []error) {
	// TODO
	return nil, nil
}
