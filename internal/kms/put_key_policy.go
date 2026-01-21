package kms

import (
	"context"
	"errors"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/nsmithuk/local-kms/internal/kms/data"
	"github.com/nsmithuk/local-kms/internal/kms/kmserr"
	"github.com/nsmithuk/local-kms/internal/kms/validation"
)

func (k KmsService) PutKeyPolicy(ctx context.Context, req awskms.PutKeyPolicyInput) (*awskms.PutKeyPolicyOutput, []error) {
	validator := validation.Validator{}
	validationErrors := make([]error, 0)

	if err := validator.RequiredPointer(req.Policy, "Policy"); err != nil {
		validationErrors = append(validationErrors, err)
	} else if err := validator.Length(req.Policy, "policy", 32768); err != nil {
		validationErrors = append(validationErrors, err)
	}

	if len(validationErrors) > 0 {
		return nil, validationErrors
	}

	keyId, err := k.ResolveKeyArn(req.KeyId)
	if err != nil {
		return nil, []error{err}
	}

	policyName := "default"
	if req.PolicyName != nil && *req.PolicyName != "" {
		policyName = *req.PolicyName
	}
	if policyName != "default" {
		return nil, []error{
			kmserr.NewValidation(kmserr.CauseValidationError, "PolicyName must be default"),
		}
	}

	key, err := k.Db.LoadKey(keyId)
	if err != nil {
		if errors.Is(err, data.ErrKeyNotFound) {
			return nil, []error{
				kmserr.NewValidation(kmserr.CauseNotFoundException, "A key with the arn %s does not exists", keyId),
			}
		}
		return nil, []error{err}
	}

	if key.IsPendingDeletion() {
		return nil, []error{
			kmserr.NewValidation(kmserr.CauseKMSInvalidStateException, "%s is pending deletion.", key.GetArn()),
		}
	}

	if err := setKeyPolicy(key, *req.Policy); err != nil {
		return nil, []error{err}
	}

	if err := k.Db.SaveKey(key); err != nil {
		return nil, []error{err}
	}

	return &awskms.PutKeyPolicyOutput{}, nil
}
