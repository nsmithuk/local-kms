package validation

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nsmithuk/local-kms/internal/kms/kmserr"
)

type Enum[T any] interface {
	comparable
	Values() []T
}

func ValidOption[T Enum[T]](value T, fieldName string) error {
	options := value.Values()
	for _, option := range options {
		if value == option {
			return nil
		}
	}

	// Not a valid value.

	values := make([]string, 0, len(options))
	for _, v := range options {
		values = append(values, fmt.Sprint(v))
	}
	sort.Strings(values)
	sortedOptions := "[" + strings.Join(values, ", ") + "]"

	return kmserr.New(
		kmserr.TypeValidation,
		kmserr.CauseUnsupportedOperationException,
		fmt.Sprintf(
			"Value '%v' at '%s' failed to satisfy constraint: Member must satisfy enum value set: %s",
			value,
			fieldName,
			sortedOptions,
		),
	)
}
