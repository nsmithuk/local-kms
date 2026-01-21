package kms

import (
	"context"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
)

func (k KmsService) ListResourceTags(ctx context.Context, req awskms.ListResourceTagsInput) (*awskms.ListResourceTagsOutput, []error) {
	// TODO
	return nil, nil
}
