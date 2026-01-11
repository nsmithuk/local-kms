package kms

import (
	"context"
	"errors"
	"strings"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/nsmithuk/local-kms/internal/kms/data"
	"github.com/nsmithuk/local-kms/internal/kms/kmserr"
	"github.com/nsmithuk/local-kms/internal/kms/validation"
)

func (k KmsService) DeleteAlias(ctx context.Context, req awskms.DeleteAliasInput) (*awskms.DeleteAliasOutput, []error) {
	validator := validation.Validator{}
	validationErrors := make([]error, 0)

	if err := validator.AliasName(req.AliasName); err != nil {
		validationErrors = append(validationErrors, err)
	}

	if len(validationErrors) > 0 {
		return nil, validationErrors
	}

	//---

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

	//---

	err = k.Db.DeleteAlias(alias)
	if err != nil {
		return nil, []error{err}
	}

	//---

	return &awskms.DeleteAliasOutput{}, nil
}
