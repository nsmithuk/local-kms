package kms

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/nsmithuk/local-kms/internal/kms/cmk"
	"github.com/nsmithuk/local-kms/internal/kms/data"
	"github.com/nsmithuk/local-kms/internal/kms/kmserr"
	"github.com/nsmithuk/local-kms/internal/kms/validation"
)

func (k KmsService) GenerateDataKeyWithoutPlaintext(ctx context.Context, req awskms.GenerateDataKeyWithoutPlaintextInput) (*awskms.GenerateDataKeyWithoutPlaintextOutput, []error) {
	dataKey, errs := k.GenerateDataKey(ctx, awskms.GenerateDataKeyInput{
		KeyId:             req.KeyId,
		EncryptionContext: req.EncryptionContext,
		KeySpec:           req.KeySpec,
		NumberOfBytes:     req.NumberOfBytes,
	})
	if errs != nil {
		return nil, errs
	}

	return &awskms.GenerateDataKeyWithoutPlaintextOutput{
		KeyId:          dataKey.KeyId,
		KeyMaterialId:  dataKey.KeyMaterialId,
		CiphertextBlob: dataKey.CiphertextBlob,
	}, nil
}

func (k KmsService) GenerateDataKey(ctx context.Context, req awskms.GenerateDataKeyInput) (*awskms.GenerateDataKeyOutput, []error) {

	validator := validation.Validator{}
	validationErrors := make([]error, 0)

	keyId, err := k.ResolveKeyArn(req.KeyId)
	if err != nil {
		validationErrors = append(validationErrors, err)
	}

	//---

	numberOfBytes := int32(0)
	if req.NumberOfBytes != nil {
		numberOfBytes = *req.NumberOfBytes
		if numberOfBytes == 0 {
			validationErrors = append(validationErrors, fmt.Errorf("number of bytes must be greater than zero"))
		} else if numberOfBytes > 1024 {
			validationErrors = append(validationErrors, fmt.Errorf("number of bytes must be less than or equal to 1024"))
		}

		if len(req.KeySpec) > 0 {
			validationErrors = append(validationErrors, fmt.Errorf("keySpec cannot be used with NumberOfBytes"))
		}
	} else {
		err = validator.DataKeySpec(req.KeySpec)
		if err != nil {
			validationErrors = append(validationErrors, err)
		}
		switch req.KeySpec {
		case types.DataKeySpecAes128:
			numberOfBytes = 128 / 8
		case types.DataKeySpecAes256:
			numberOfBytes = 256 / 8
		default:
			validationErrors = append(validationErrors, fmt.Errorf("keySpec must be one of AES_256 | AES_128"))
		}
	}

	if len(validationErrors) > 0 {
		return nil, validationErrors
	}

	//---

	key, err := k.Db.LoadKey(keyId)
	if err != nil {
		if errors.Is(err, data.ErrKeyNotFound) {
			return nil, []error{
				kmserr.NewValidation(kmserr.CauseNotFoundException, "A key with the arn %s does not exists", keyId),
			}
		}
		return nil, []error{err}
	}

	if key.GetKeyType() != cmk.TypeSymmetricKey {
		return nil, []error{
			fmt.Errorf("keyspec must be %s", types.KeySpecSymmetricDefault),
		}
	}

	//---

	plaintext := cmk.GenerateRandomData(numberOfBytes)

	encrypt, errs := k.Encrypt(ctx, awskms.EncryptInput{
		KeyId:               aws.String(key.GetArn()),
		Plaintext:           plaintext,
		EncryptionAlgorithm: types.EncryptionAlgorithmSpecSymmetricDefault,
		EncryptionContext:   req.EncryptionContext,
	})

	if errs != nil {
		return nil, errs
	}

	return &awskms.GenerateDataKeyOutput{
		KeyId:          encrypt.KeyId,
		KeyMaterialId:  key.GetMetadata().CurrentKeyMaterialId,
		Plaintext:      plaintext,
		CiphertextBlob: encrypt.CiphertextBlob,
	}, nil
}
