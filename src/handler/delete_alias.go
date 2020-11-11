package handler

import (
	"fmt"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/nsmithuk/local-kms/src/config"
	"strings"
)

func (r *RequestHandler) DeleteAlias() Response {

	var body *kms.DeleteAliasInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.DeleteAliasInput{}
	}

	//--------------------------------
	// Validation

	if body.AliasName == nil {
		msg := "AliasName is a required parameter"

		r.logger.Warnf(msg)
		return NewMissingParameterResponse(msg)
	}

	if !strings.HasPrefix(*body.AliasName, "alias/") {
		msg := "Alias must start with the prefix \"alias/\". Please see " +
			"http://docs.aws.amazon.com/kms/latest/developerguide/programming-aliases.html"

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg)
	}

	if strings.HasPrefix(*body.AliasName, "alias/aws") {
		r.logger.Warnf("Cannot remove alias with prefix 'alias/aws/'")
		return NewNotAuthorizedExceptionResponse("")
	}

	//--------------------------------

	aliasArn := config.ArnPrefix() + *body.AliasName

	_, err = r.database.LoadAlias(aliasArn)

	if err != nil {
		msg := fmt.Sprintf("Alias '%s' does not exist", aliasArn)

		r.logger.Warnf(msg)
		return NewNotFoundExceptionResponse(msg)
	}

	r.database.DeleteObject(aliasArn)

	//---

	r.logger.Infof("Alias deleted: %s\n", aliasArn)

	return NewResponse(200, nil)
}
