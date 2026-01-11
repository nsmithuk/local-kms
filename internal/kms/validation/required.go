package validation

import (
	"fmt"

	"github.com/nsmithuk/local-kms/internal/kms/kmserr"
)

func (v *Validator) RequiredString(value string, field string) error {
	if len(value) == 0 {
		return kmserr.New(
			kmserr.TypeValidation,
			kmserr.CauseValidationError,
			fmt.Sprintf("'%s' is a required field", field),
		)
	}
	return nil
}

func (v *Validator) RequiredPointer(value any, field string) error {
	if value == nil {
		return kmserr.New(
			kmserr.TypeValidation,
			kmserr.CauseValidationError,
			fmt.Sprintf("'%s' is a required field", field),
		)
	}
	return nil
}
