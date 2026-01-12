package validation

import (
	"fmt"
	"sort"
	"strings"

	awskmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/nsmithuk/local-kms/internal/kms/kmserr"
)

func KeyPairSpec(value awskmstypes.DataKeyPairSpec) error {
	options := value.Values()
	for _, option := range options {
		if value == option {
			return nil
		}
	}

	// Not a valid value.

	// Sort the values
	values := make([]string, 0, len(options))
	for _, v := range options {
		values = append(values, string(v))
	}
	sort.Strings(values)
	sortedOptions := "[" + strings.Join(values, ", ") + "]"

	//----

	return kmserr.New(
		kmserr.TypeValidation,
		kmserr.CauseUnsupportedOperationException,
		fmt.Sprintf("Value '%s' at 'KeyPairSpec' failed to satisfy constraint: "+
			"Member must satisfy enum value set: %s", value, sortedOptions),
	)
}
