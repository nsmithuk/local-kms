package kms

import (
	"context"
	"errors"
	"strings"
	"time"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/nsmithuk/local-kms/internal/kms/data"
	"github.com/nsmithuk/local-kms/internal/kms/kmserr"
	"github.com/nsmithuk/local-kms/internal/kms/validation"
)

func (k KmsService) UpdateAlias(ctx context.Context, req awskms.UpdateAliasInput) (*awskms.UpdateAliasOutput, []error) {
	validator := validation.Validator{}
	validationErrors := make([]error, 0)

	if err := validator.AliasName(req.AliasName); err != nil {
		validationErrors = append(validationErrors, err)
	}
	if err := validator.AliasKeyId(req.TargetKeyId); err != nil {
		validationErrors = append(validationErrors, err)
	}
	if err := validator.Length(req.AliasName, "AliasName", 256); err != nil {
		validationErrors = append(validationErrors, err)
	}

	if len(validationErrors) > 0 {
		return nil, validationErrors
	}

	targetKeyArn, err := k.ResolveKeyArn(req.TargetKeyId)
	if err != nil {
		return nil, []error{err}
	}

	key, err := k.Db.LoadKey(targetKeyArn)
	if err != nil {
		if errors.Is(err, data.ErrKeyNotFound) {
			return nil, []error{
				kmserr.NewValidation(kmserr.CauseNotFoundException, "Key %s not found.", targetKeyArn),
			}
		}
		return nil, []error{err}
	}

	if key.IsPendingDeletion() {
		return nil, []error{
			kmserr.NewValidation(kmserr.CauseKMSInvalidStateException, "%s is pending deletion.", key.GetArn()),
		}
	}

	aliasArn := k.ArnPrefix() + "alias/" + strings.TrimPrefix(*req.AliasName, "alias/")
	alias, err := k.Db.LoadAlias(aliasArn)
	if err != nil {
		if errors.Is(err, data.ErrAliasNotFound) {
			return nil, []error{
				kmserr.NewValidation(kmserr.CauseNotFoundException, "An alias with the name %s does not exists", *req.AliasName),
			}
		}
		return nil, []error{err}
	}

	now := time.Now()
	alias.TargetKeyId = &targetKeyArn
	alias.LastUpdatedDate = &now

	if err := k.Db.SaveAlias(alias); err != nil {
		return nil, []error{err}
	}

	return &awskms.UpdateAliasOutput{}, nil
}
