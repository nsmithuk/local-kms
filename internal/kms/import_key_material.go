package kms

import (
	"bytes"
	"context"
	"crypto/sha3"
	"crypto/subtle"
	"errors"
	"log/slog"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/nsmithuk/local-kms/internal/kms/cmk"
	"github.com/nsmithuk/local-kms/internal/kms/kmserr"
	"github.com/nsmithuk/local-kms/internal/kms/validation"
)

func (k KmsService) ImportKeyMaterial(ctx context.Context, req awskms.ImportKeyMaterialInput) (*awskms.ImportKeyMaterialOutput, []error) {

	validator := validation.Validator{}

	if err := validator.ExpirationModel(req.ExpirationModel); err != nil {
		return nil, []error{err}
	}

	if req.ExpirationModel == types.ExpirationModelTypeKeyMaterialExpires {
		if req.ValidTo == nil {
			return nil, []error{
				kmserr.NewValidation(kmserr.CauseValidationError, "Value at 'validTo' failed to satisfy constraint: Member must not be null when ExpirationModel is KEY_MATERIAL_EXPIRES"),
			}
		}
		if !time.Now().Before(*req.ValidTo) {
			return nil, []error{
				kmserr.NewValidation(kmserr.CauseValidationError, "Value at 'validTo' failed to satisfy constraint: Member must be in the future"),
			}
		}
	} else if req.ValidTo != nil {
		return nil, []error{
			kmserr.NewValidation(kmserr.CauseValidationError, "Value at 'validTo' failed to satisfy constraint: Member must be null when ExpirationModel is KEY_MATERIAL_DOES_NOT_EXPIRE"),
		}
	}

	if req.ImportType == "" {
		req.ImportType = types.ImportTypeNewKeyMaterial
	}
	if err := validator.ImportType(req.ImportType); err != nil {
		return nil, []error{err}
	}

	if len(req.EncryptedKeyMaterial) == 0 {
		return nil, []error{
			errors.New("missing keymaterial"),
		}
	}

	key, err := k.getKeyWithState(req.KeyId, types.KeyStatePendingImport)
	if err != nil {
		key, err = k.getUsableKey(req.KeyId)
		if err != nil {
			return nil, []error{err}
		}
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

	digest := sha3.SumSHAKE256(unwrappedKey, 8)

	if _, isSymmetric := key.(*cmk.SymmetricKey); !isSymmetric {
		// Detect if the material has changed.
		// Symmetric Keys have their own way of doing this.

		if key.GetLastImportDigest() != nil && !bytes.Equal(key.GetLastImportDigest(), digest) {
			return nil, []error{
				kmserr.NewValidation(kmserr.CauseIncorrectKeyMaterialException, "Imported key material did not match expected digest"),
			}
		}
	}

	//---

	err = key.ApplyImportedKeyMaterial(unwrappedKey, req.KeyMaterialId, req.ImportType)
	if err != nil {
		return nil, []error{err}
	}

	key.GetMetadata().ExpirationModel = req.ExpirationModel
	key.GetMetadata().ValidTo = req.ValidTo

	//---

	key.GetMetadata().KeyState = types.KeyStateEnabled

	//---

	key.SetLastImportDigest(digest)

	err = k.Db.SaveKey(key)
	if err != nil {
		return nil, []error{err}
	}

	//---

	slog.Info("ImportKeyMaterial Success",
		"KeyId", *key.GetMetadata().KeyId,
		"KeySpec", key.GetMetadata().KeySpec,
	)

	return &awskms.ImportKeyMaterialOutput{
		KeyId:         aws.String(key.GetArn()),
		KeyMaterialId: key.GetMetadata().CurrentKeyMaterialId,
	}, nil
}
