package kms

import (
	"context"
	"errors"
	"fmt"
	"slices"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/nsmithuk/local-kms/internal/kms/data"
	"github.com/nsmithuk/local-kms/internal/kms/kmserr"
)

func (k KmsService) UntagResource(ctx context.Context, req awskms.UntagResourceInput) (*awskms.UntagResourceOutput, []error) {
	if len(req.TagKeys) == 0 {
		return nil, []error{
			kmserr.NewValidation(kmserr.CauseValidationError, "'TagKeys' is a required field"),
		}
	}

	for i, tagKey := range req.TagKeys {
		if len(tagKey) < 1 {
			return nil, []error{
				kmserr.New(
					kmserr.TypeValidation,
					kmserr.CauseTagException,
					fmt.Sprintf("Value '' at 'tags.%d.member.tagKey' failed to satisfy constraint: Member must have length greater than or equal to 1", i+1),
				),
			}
		}

		if len(tagKey) > 128 {
			return nil, []error{
				kmserr.New(
					kmserr.TypeValidation,
					kmserr.CauseTagException,
					fmt.Sprintf("Value '%s' at 'tags.%d.member.tagKey' failed to satisfy constraint: Member must have length less than or equal to 128", tagKey, i+1),
				),
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

	if key.IsPendingDeletion() {
		return nil, []error{
			kmserr.NewValidation(kmserr.CauseKMSInvalidStateException, "%s is pending deletion.", key.GetArn()),
		}
	}

	remainingTags := make([]*types.Tag, 0)
	marker := ""
	for {
		tags, err := k.Db.ListTags(key.GetArn(), 100, marker)
		if err != nil {
			return nil, []error{err}
		}

		for _, tag := range tags {
			if tag.TagKey != nil && !slices.Contains(req.TagKeys, *tag.TagKey) {
				remainingTags = append(remainingTags, tag)
			}
		}

		if len(tags) < 100 {
			break
		}

		lastTag := tags[len(tags)-1]
		if lastTag.TagKey == nil {
			break
		}
		marker = "tag/" + key.GetArn() + "/" + *lastTag.TagKey
	}

	if err := k.Db.DeleteTag(key); err != nil {
		return nil, []error{err}
	}

	for _, tag := range remainingTags {
		if tag == nil {
			continue
		}
		if err := k.Db.SaveTag(key, *tag); err != nil {
			return nil, []error{err}
		}
	}

	return &awskms.UntagResourceOutput{}, nil
}
