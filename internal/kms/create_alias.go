package kms

import (
	"context"
	"errors"
	"strings"
	"time"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/nsmithuk/local-kms/internal/kms/data"
	"github.com/nsmithuk/local-kms/internal/kms/kmserr"
	"github.com/nsmithuk/local-kms/internal/kms/validation"
)

func (k KmsService) CreateAlias(ctx context.Context, req awskms.CreateAliasInput) (*awskms.CreateAliasOutput, []error) {
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

	//---

	targetKeyArn, err := k.ResolveKeyArn(req.TargetKeyId)
	if err != nil {
		return nil, []error{err}
	}

	key, err := k.Db.LoadKey(targetKeyArn)
	if err != nil {
		if !errors.Is(err, data.ErrKeyNotFound) {
			return nil, []error{
				kmserr.NewValidation(kmserr.CauseNotFoundException, "Key %s not found.", key.GetArn()),
			}
		}
		return nil, []error{err}
	}

	if key.IsPendingDeletion() {
		return nil, []error{
			kmserr.NewValidation(kmserr.CauseKMSInvalidStateException, "%s is pending deletion.", key.GetArn()),
		}
	}

	//---

	aliasArn := k.ArnPrefix() + "alias/" + strings.TrimPrefix(*req.AliasName, "alias/")
	if _, err := k.Db.LoadAlias(aliasArn); err == nil {
		return nil, []error{
			kmserr.NewValidation(kmserr.CauseAlreadyExistsException, "An alias with the name %s already exists", *req.AliasName),
		}
	} else if !errors.Is(err, data.ErrAliasNotFound) {
		return nil, []error{err}
	}

	//---

	now := time.Now()

	alias := types.AliasListEntry{
		AliasArn:        &aliasArn,
		AliasName:       req.AliasName,
		CreationDate:    &now,
		LastUpdatedDate: &now,
		TargetKeyId:     &targetKeyArn,
	}

	if err := k.Db.SaveAlias(alias); err != nil {
		return nil, []error{err}
	}

	return &awskms.CreateAliasOutput{}, nil
}
