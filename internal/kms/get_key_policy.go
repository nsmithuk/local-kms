package kms

import (
	"context"
	"errors"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/nsmithuk/local-kms/internal/kms/data"
	"github.com/nsmithuk/local-kms/internal/kms/kmserr"
)

func (k KmsService) GetKeyPolicy(ctx context.Context, req awskms.GetKeyPolicyInput) (*awskms.GetKeyPolicyOutput, []error) {
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

	policy := key.GetPolicy()

	return &awskms.GetKeyPolicyOutput{
		Policy:     &policy,
		PolicyName: &policyName,
	}, nil
}
