package kms

import (
	"context"
	"errors"
	"fmt"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/nsmithuk/local-kms/internal/kms/data"
	"github.com/nsmithuk/local-kms/internal/kms/kmserr"
)

func (k KmsService) ListKeyPolicies(ctx context.Context, req awskms.ListKeyPoliciesInput) (*awskms.ListKeyPoliciesOutput, []error) {
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

	keyId, err := k.ResolveKeyArn(req.KeyId)
	if err != nil {
		return nil, []error{err}
	}

	_, err = k.Db.LoadKey(keyId)
	if err != nil {
		if errors.Is(err, data.ErrKeyNotFound) {
			return nil, []error{
				kmserr.NewValidation(kmserr.CauseNotFoundException, "A key with the arn %s does not exists", keyId),
			}
		}
		return nil, []error{err}
	}

	var marker *string
	if req.Marker != nil {
		marker, err = DecodeMarker(req.Marker)
		if err != nil {
			return nil, []error{err}
		}
	}

	if marker != nil && *marker != "default" {
		return nil, []error{fmt.Errorf("%w: %s", data.ErrInvalidMarker, *marker)}
	}

	if marker != nil && *marker == "default" {
		return &awskms.ListKeyPoliciesOutput{
			PolicyNames: nil,
			Truncated:   false,
		}, nil
	}

	policies := []string{"default"}
	if limit < 1 {
		policies = nil
	}

	return &awskms.ListKeyPoliciesOutput{
		PolicyNames: policies,
		Truncated:   false,
	}, nil
}
