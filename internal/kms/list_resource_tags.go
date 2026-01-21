package kms

import (
	"context"
	"errors"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/nsmithuk/local-kms/internal/kms/data"
	"github.com/nsmithuk/local-kms/internal/kms/kmserr"
)

func (k KmsService) ListResourceTags(ctx context.Context, req awskms.ListResourceTagsInput) (*awskms.ListResourceTagsOutput, []error) {
	limit := int32(50)
	if req.Limit != nil {
		limit = *req.Limit

		if limit < 1 || limit > 50 {
			return nil, []error{
				kmserr.NewValidation(kmserr.CauseValidationError, "Value '%d' at 'limit' failed to satisfy "+
					"constraint: Minimum value of 1. Maximum value of 50.", limit),
			}
		}
	}

	keyId, err := k.ResolveKeyArn(req.KeyId)
	if err != nil {
		return nil, []error{err}
	}

	key, err := k.Db.LoadKey(keyId)
	if err != nil {
		if errors.Is(err, data.ErrKeyNotFound) {
			return nil, []error{
				kmserr.NewValidation(kmserr.CauseNotFoundException, "A key with the arn %s does not exists", keyId),
			}
		}
		return nil, []error{err}
	}

	reqMarker := req.Marker
	if reqMarker != nil {
		reqMarker, err = DecodeMarker(reqMarker)
		if err != nil {
			return nil, []error{err}
		}
	}

	fetchLimit := int64(limit + 1)
	marker := ""
	if reqMarker != nil {
		marker = *reqMarker
	}

	tagEntries, err := k.Db.ListTags(key.GetArn(), fetchLimit, marker)
	if err != nil {
		return nil, []error{err}
	}

	truncated := false
	var nextMarker *string

	if int32(len(tagEntries)) > limit {
		truncated = true
		tagEntries = tagEntries[:limit]
		lastTag := tagEntries[len(tagEntries)-1]
		if lastTag.TagKey != nil {
			nextMarker = EncodeMarker("tag/" + key.GetArn() + "/" + *lastTag.TagKey)
		}
	}

	tags := make([]types.Tag, 0, len(tagEntries))
	for _, tag := range tagEntries {
		if tag == nil {
			continue
		}
		tags = append(tags, *tag)
	}

	return &awskms.ListResourceTagsOutput{
		NextMarker: nextMarker,
		Tags:       tags,
		Truncated:  truncated,
	}, nil
}
