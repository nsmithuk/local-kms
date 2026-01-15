package kms

import (
	"bytes"
	"context"
	"crypto/sha3"
	"crypto/subtle"
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/nsmithuk/local-kms/internal/kms/kmserr"
	"github.com/nsmithuk/local-kms/internal/kms/validation"
)

func (k KmsService) ImportKeyMaterial(ctx context.Context, req awskms.ImportKeyMaterialInput) (*awskms.ImportKeyMaterialOutput, []error) {

	if err := validation.ValidateEnum(req.ExpirationModel, "ExpirationModel"); err != nil {
		return nil, []error{err}
	}

	if req.ImportType == "" {
		req.ImportType = types.ImportTypeNewKeyMaterial
	}
	if err := validation.ValidateEnum(req.ImportType, "ImportType"); err != nil {
		return nil, []error{err}
	}

	if len(req.EncryptedKeyMaterial) == 0 {
		return nil, []error{
			errors.New("missing keymaterial"),
		}
	}

	key, err := k.getKeyWithState(req.KeyId, types.KeyStatePendingImport)
	if err != nil {
		return nil, []error{err}
	}

	params := key.GetParametersForImport()
	if params == nil {
		return nil, []error{
			kmserr.NewValidation(kmserr.CauseKMSInvalidStateException, "key is not in a state to support importing material"),
		}
	}

	if subtle.ConstantTimeCompare(params.ImportToken, req.ImportToken) == 0 {
		return nil, []error{
			kmserr.NewValidation(kmserr.CauseInvalidImportTokenException, "key is not in a state to support importing material"),
		}
	}

	//---

	unwrappedKey, err := params.UnwrapKeyMaterial(req.EncryptedKeyMaterial)
	if err != nil {
		return nil, []error{err}
	}

	//---

	// Detect if the material has changed.
	digest := sha3.SumSHAKE256(unwrappedKey, 8)

	if key.GetLastImportDigest() != nil && !bytes.Equal(key.GetLastImportDigest(), digest) {
		return nil, []error{
			kmserr.NewValidation(kmserr.CauseIncorrectKeyMaterialException, "Imported key material did not match expected digest"),
		}
	}

	//---

	err = key.ApplyImportedKeyMaterial(unwrappedKey, req.KeyMaterialId, req.ImportType)
	if err != nil {
		return nil, []error{err}
	}

	// TODO: ValidTo

	//---

	//symmetric, isSymmetric := key.(*cmk.SymmetricKey)
	//if isSymmetric {
	//
	//}

	//---

	key.GetMetadata().KeyState = types.KeyStateEnabled

	//---

	key.SetLastImportDigest(digest)

	err = k.Db.SaveKey(key)
	if err != nil {
		return nil, []error{err}
	}

	//---

	return &awskms.ImportKeyMaterialOutput{
		KeyId:         aws.String(key.GetArn()),
		KeyMaterialId: key.GetMetadata().CurrentKeyMaterialId,
	}, nil
}
