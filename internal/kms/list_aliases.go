package kms

import (
	"context"
	"errors"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/nsmithuk/local-kms/internal/kms/data"
	"github.com/nsmithuk/local-kms/internal/kms/kmserr"
)

func (k KmsService) ListAliases(ctx context.Context, req awskms.ListAliasesInput) (*awskms.ListAliasesOutput, []error) {
	limit := int32(50)
	if req.Limit != nil {
		limit = *req.Limit

		if limit < 1 || limit > 100 {
			return nil, []error{
				kmserr.NewValidation(kmserr.CauseValidationError, "Value '%d' at 'limit' failed to satisfy "+
					"constraint: Minimum value of 1. Maximum value of 100.", limit),
			}
		}
	}

	var keyArn string
	if req.KeyId != nil {
		var err error
		keyArn, err = k.ResolveKeyArn(req.KeyId)
		if err != nil {
			return nil, []error{err}
		}

		if _, err := k.Db.LoadKey(keyArn); err != nil {
			if errors.Is(err, data.ErrKeyNotFound) {
				return nil, []error{
					kmserr.NewValidation(kmserr.CauseNotFoundException, "A key with the arn %s does not exists", keyArn),
				}
			}
			return nil, []error{err}
		}
	}

	reqMarker := req.Marker
	if reqMarker != nil {
		var err error
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

	aliases, err := k.Db.ListAlias("", fetchLimit, marker, keyArn)
	if err != nil {
		return nil, []error{err}
	}

	truncated := false
	var nextMarker *string

	if int32(len(aliases)) > limit {
		truncated = true
		aliases = aliases[:limit]
		lastAlias := aliases[len(aliases)-1]
		if lastAlias.AliasArn != nil {
			nextMarker = EncodeMarker("alias/" + *lastAlias.AliasArn)
		}
	}

	outputAliases := make([]types.AliasListEntry, 0, len(aliases))
	for _, alias := range aliases {
		outputAliases = append(outputAliases, alias)
	}

	return &awskms.ListAliasesOutput{
		Aliases:    outputAliases,
		NextMarker: nextMarker,
		Truncated:  truncated,
	}, nil
}
