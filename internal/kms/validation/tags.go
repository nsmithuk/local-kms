package validation

import (
	"fmt"

	awskmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/nsmithuk/local-kms/internal/kms/kmserr"
)

func (v *Validator) Tags(tags []awskmstypes.Tag) []error {
	validationErrors := make([]error, 0)

	if tags != nil && len(tags) > 0 {
		for i, tag := range tags {

			if len(*tag.TagKey) < 1 {
				err := kmserr.New(
					kmserr.TypeValidation,
					kmserr.CauseTagException,
					fmt.Sprintf("Value '' at 'tags.%d.member.tagKey' failed to "+
						"satisfy constraint: Member must have length greater than or equal to 1", i+1),
				)
				validationErrors = append(validationErrors, err)
			}

			if len(*tag.TagKey) > 128 {
				err := kmserr.New(
					kmserr.TypeValidation,
					kmserr.CauseTagException,
					fmt.Sprintf("Value '%s' at 'tags.%d.member.tagKey' failed to satisfy "+
						"constraint: Member must have length less than or equal to 128", *tag.TagKey, i+1),
				)
				validationErrors = append(validationErrors, err)
			}

			if len(*tag.TagValue) > 256 {
				err := kmserr.New(
					kmserr.TypeValidation,
					kmserr.CauseTagException,
					fmt.Sprintf("Value '%s' at 'tags.%d.member.tagValue' failed to "+
						"satisfy constraint: Member must have length less than or equal to 256", *tag.TagValue, i+1),
				)
				validationErrors = append(validationErrors, err)
			}

		}
	}

	return validationErrors
}
