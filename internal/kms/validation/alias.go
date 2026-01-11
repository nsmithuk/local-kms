package validation

import (
	"strings"

	"github.com/nsmithuk/local-kms/internal/kms/kmserr"
)

func (*Validator) AliasName(name *string) error {
	if name == nil || *name == "" {
		return kmserr.NewValidation(kmserr.CauseValidationError, "AliasName is a required parameter")
	}
	if !strings.HasPrefix(*name, "alias/") {
		return kmserr.NewValidation(kmserr.CauseInvalidAliasNameException, "AliasName must start with 'alias/'")
	}
	if strings.HasPrefix(*name, "alias/aws/") || *name == "alias/aws" {
		return kmserr.NewValidation(kmserr.CauseInvalidAliasNameException, "Aliases with prefix 'alias/aws/' are reserved")
	}
	return nil
}

func (*Validator) AliasKeyId(id *string) error {
	if id == nil || *id == "" {
		return kmserr.NewValidation(kmserr.CauseValidationError, "'TargetKeyId' is a required field")
	}
	if strings.HasPrefix(*id, "alias/") {
		return kmserr.NewValidation(kmserr.CauseValidationError, "'TargetKeyId' cannot be another alias")
	}
	return nil
}
