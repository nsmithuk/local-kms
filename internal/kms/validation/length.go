package validation

import (
	"fmt"

	"github.com/nsmithuk/local-kms/internal/kms/kmserr"
)

type Validator struct {
}

func (*Validator) Length(value *string, field string, max int) error {
	if value != nil && len(*value) > max {
		return kmserr.New(
			kmserr.TypeValidation,
			kmserr.CauseLimitExceededException,
			fmt.Sprintf("Value '%s' at '%s' failed to satisfy "+
				"constraint: Member must have length less than or equal to %d", *value, field, max),
		)
	}
	return nil
}

func (*Validator) ByteLength(value []byte, field string, max int) error {
	if value != nil && len(value) > max {
		return kmserr.New(
			kmserr.TypeValidation,
			kmserr.CauseLimitExceededException,
			fmt.Sprintf("Value at '%s' failed to satisfy "+
				"constraint: Member must have length less than or equal to %d bytes", field, max),
		)
	}
	return nil
}

func ByteLength(value []byte, field string, max int) error {
	if value != nil && len(value) > max {
		return kmserr.New(
			kmserr.TypeValidation,
			kmserr.CauseLimitExceededException,
			fmt.Sprintf("Value at '%s' failed to satisfy "+
				"constraint: Member must have length less than or equal to %d bytes", field, max),
		)
	}
	return nil
}
