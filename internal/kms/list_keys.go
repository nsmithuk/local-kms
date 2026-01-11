package kms

import (
	"context"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/nsmithuk/local-kms/internal/kms/kmserr"
)

func (k KmsService) ListKeys(ctx context.Context, req awskms.ListKeysInput) (*awskms.ListKeysOutput, []error) {
	limit := int32(100)
	if req.Limit != nil {
		limit = *req.Limit

		if limit < 1 || limit > 1000 {
			return nil, []error{
				kmserr.NewValidation(kmserr.CauseValidationError, "Value '%d' at 'limit' failed to satisfy "+
					"constraint: Minimum value of 1. Maximum value of 1000.", limit),
			}
		}
	}

	reqNextMarker := req.Marker
	if reqNextMarker != nil {
		var err error
		reqNextMarker, err = DecodeMarker(reqNextMarker)
		if err != nil {
			return nil, []error{err}
		}
	}

	fetchLimit := limit + 1

	keys, err := k.Db.ListKeys(fetchLimit, reqNextMarker)
	if err != nil {
		return nil, []error{err}
	}

	truncated := false
	var nextMarker *string

	// We use the ARN of the last returned key as a marker
	if int32(len(keys)) > limit {
		truncated = true
		keys = keys[:limit]
		lastArn := keys[len(keys)-1].GetArn()
		nextMarker = EncodeMarker(lastArn)
	}

	entries := make([]types.KeyListEntry, 0, len(keys))
	for _, key := range keys {
		meta := key.GetMetadata()
		entries = append(entries, types.KeyListEntry{KeyArn: meta.Arn, KeyId: meta.KeyId})
	}

	return &awskms.ListKeysOutput{Keys: entries, NextMarker: nextMarker, Truncated: truncated}, nil
}
