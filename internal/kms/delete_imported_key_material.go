package kms

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

func (k KmsService) DeleteImportedKeyMaterial(ctx context.Context, req awskms.DeleteImportedKeyMaterialInput) (*awskms.DeleteImportedKeyMaterialOutput, []error) {
	// We can apply to enabled and pending deleted.
	key, err := k.getKeyWithState(req.KeyId, types.KeyStatePendingDeletion)
	if err != nil {
		key, err = k.getUsableKey(req.KeyId)
		if err != nil {
			return nil, []error{err}
		}
	}

	//---

	//symmetric, isSymmetric := key.(*cmk.SymmetricKey)
	//if isSymmetric {
	//
	//}

	//---

	err = key.DeleteImportedKeyMaterial(req.KeyMaterialId)
	if err != nil {
		return nil, []error{err}
	}

	if key.GetMetadata().KeyState != types.KeyStatePendingDeletion {
		key.GetMetadata().KeyState = types.KeyStatePendingImport
	}

	//---

	err = k.Db.SaveKey(key)
	if err != nil {
		return nil, []error{err}
	}

	//---

	return &awskms.DeleteImportedKeyMaterialOutput{
		KeyId:         aws.String(key.GetArn()),
		KeyMaterialId: req.KeyMaterialId,
	}, nil
}
