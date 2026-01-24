package kms

import (
	"context"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// TODO: Import keys (and thus ListKeyRotations) is not functionally complete.

func (k KmsService) ListKeyRotations(ctx context.Context, req awskms.ListKeyRotationsInput) (*awskms.ListKeyRotationsOutput, []error) {

	key, err := k.getKeyWithState(req.KeyId, types.KeyStatePendingImport)
	if err != nil {
		key, err = k.getUsableKey(req.KeyId)
		if err != nil {
			return nil, []error{err}
		}
	}

	if req.IncludeKeyMaterial == "" {
		// TODO: Note that this isn't used at the moment.
		req.IncludeKeyMaterial = types.IncludeKeyMaterialRotationsOnly
	}

	rotations := key.ListKeyRotations(req.IncludeKeyMaterial)

	return &awskms.ListKeyRotationsOutput{
		Rotations: rotations,
		Truncated: false,
	}, nil
}
