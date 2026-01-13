package kms

import (
	"context"
	"errors"
	"fmt"
	"time"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/google/uuid"
	"github.com/nsmithuk/local-kms/internal/kms/cmk"
	"github.com/nsmithuk/local-kms/internal/kms/kmserr"
	"github.com/nsmithuk/local-kms/internal/kms/validation"
)

func (k KmsService) CreateKeyWithoutMaterial(ctx context.Context, req awskms.CreateKeyInput, keyId string) (cmk.Key, []error) {
	arn := k.ArnPrefix() + "key/" + keyId
	now := time.Now()
	boolFalse := false

	metadata := types.KeyMetadata{
		KeyId:                       &keyId,          // ✅
		AWSAccountId:                &k.AWSAccountId, // ✅
		Arn:                         &arn,            // ✅
		CloudHsmClusterId:           nil,
		CreationDate:                &now, // ✅
		CurrentKeyMaterialId:        nil,
		CustomKeyStoreId:            nil,
		CustomerMasterKeySpec:       "",
		DeletionDate:                nil,
		Description:                 req.Description, // ✅
		Enabled:                     true,            // ✅
		EncryptionAlgorithms:        nil,
		ExpirationModel:             "",
		KeyAgreementAlgorithms:      nil,
		KeyManager:                  types.KeyManagerTypeCustomer, // ✅
		KeySpec:                     req.KeySpec,                  // ✅
		KeyState:                    types.KeyStateEnabled,        // ✅
		KeyUsage:                    req.KeyUsage,
		MacAlgorithms:               nil,
		MultiRegion:                 &boolFalse,
		MultiRegionConfiguration:    nil,
		Origin:                      req.Origin, // ✅
		PendingDeletionWindowInDays: nil,
		SigningAlgorithms:           nil,
		ValidTo:                     nil,
		XksKeyConfiguration:         nil,
	}

	//--------------------------------
	// Validation

	validator := validation.Validator{}

	validationErrors := make([]error, 0)

	if err := validator.Length(req.Description, "description", 8192); err != nil {
		validationErrors = append(validationErrors, err)
	}

	if err := validator.Length(req.Policy, "policy", 32768); err != nil {
		validationErrors = append(validationErrors, err)
	}

	if errs := validator.Tags(req.Tags); len(errs) > 0 {
		validationErrors = append(validationErrors, errs...)
	}

	//---------------------------

	if metadata.Description == nil {
		emptyString := ""
		metadata.Description = &emptyString
	}

	//---------------------------
	// Apply the default policy

	// The default
	policy := fmt.Sprintf(`{
			"Id": "key-default-policy",
			"Version": "2012-10-17",
			"Statement": [{
				"Sid": "Enable IAM User Permissions",
				"Effect": "Allow",
				"Principal": {
					"AWS": "arn:aws:iam::%s:root"
				},
				"Action": "kms:*",
				"Resource": "*"
			}]
		}`, k.AWSAccountId)

	if req.Policy != nil {
		policy = *req.Policy
	}

	//----------------------------
	// Origin

	if metadata.Origin == types.OriginTypeExternal {
		metadata.KeyState = types.KeyStatePendingImport
	}
	if metadata.Origin == types.OriginTypeAwsCloudhsm {
		validationErrors = append(
			validationErrors,
			errors.New("Local KMS does not support Origin = AWS_CLOUDHSM"),
		)
	}
	if metadata.Origin == types.OriginTypeExternalKeyStore {
		validationErrors = append(
			validationErrors,
			errors.New("Local KMS does not support Origin = EXTERNAL_KEY_STORE"),
		)
	}
	if metadata.Origin == "" {
		// Use the default
		metadata.Origin = types.OriginTypeAwsKms
	}

	// Validate
	if err := validator.Origin(metadata.Origin); err != nil {
		validationErrors = append(validationErrors, err)
	}

	//----------------------------
	// KeySpec

	// We're already set metadata.KeySpec = req.KeySpec

	if metadata.KeySpec != "" && req.CustomerMasterKeySpec != "" {
		// Both values cannot be set
		validationErrors = append(
			validationErrors,
			kmserr.NewValidation(kmserr.CauseValidationError, "You cannot specify KeySpec and CustomerMasterKeySpec in the same request. CustomerMasterKeySpec is deprecated."),
		)
	}

	if metadata.KeySpec == "" && req.CustomerMasterKeySpec != "" {
		// If we only have CustomerMasterKeySpec, copy it over to KeySpec
		metadata.KeySpec = types.KeySpec(req.CustomerMasterKeySpec)
	}
	if metadata.KeySpec == "" {
		// The default
		metadata.KeySpec = types.KeySpecSymmetricDefault
	}
	if metadata.KeySpec == "SM2" {
		validationErrors = append(
			validationErrors,
			errors.New("Local KMS does not (yet) support KeySpec = SM2"),
		)
	}

	// Validate
	if err := validator.KeySpec(metadata.KeySpec); err != nil {
		validationErrors = append(validationErrors, err)
	}

	//----------------------------
	// Create the key

	var key cmk.Key
	var err error

	switch metadata.KeySpec {
	case types.KeySpecSymmetricDefault:
		key, err = cmk.NewSymmetricKey(metadata, policy)
	case types.KeySpecRsa2048, types.KeySpecRsa3072, types.KeySpecRsa4096:
		key, err = cmk.NewRsaKey(metadata, policy)
	case types.KeySpecMlDsa44, types.KeySpecMlDsa65, types.KeySpecMlDsa87:
		key, err = cmk.NewMlDsaKey(metadata, policy)
	case types.KeySpecHmac224, types.KeySpecHmac256, types.KeySpecHmac384, types.KeySpecHmac512:
		key, err = cmk.NewHmacKey(metadata, policy)
	case types.KeySpecEccNistP256, types.KeySpecEccNistP384, types.KeySpecEccNistP521, types.KeySpecEccSecgP256k1:
		key, err = cmk.NewEcdsaKey(metadata, policy)
	case types.KeySpecEccNistEdwards25519:
		key, err = cmk.NewEd25519Key(metadata, policy)
	}

	if err != nil {
		validationErrors = append(validationErrors, err)
	}

	if len(validationErrors) > 0 {
		return nil, validationErrors
	}

	//---

	return key, nil
}

func (k KmsService) CreateKey(ctx context.Context, req awskms.CreateKeyInput) (*awskms.CreateKeyOutput, []error) {

	keyId := uuid.NewString()

	key, errs := k.CreateKeyWithoutMaterial(ctx, req, keyId)
	if errs != nil && len(errs) > 0 {
		return nil, errs
	}

	if key.GetMetadata().Origin == types.OriginTypeAwsKms {
		// We only apply material if the expected origin is KMS.
		err := key.ApplyNewKeyMaterial()
		if err != nil {
			return nil, []error{err}
		}
	}

	//----------------------------
	// Save the key

	err := k.Db.SaveKey(key)
	if err != nil {
		return nil, []error{err}
	}

	//----------------------------
	// Save the tags

	if req.Tags != nil && len(req.Tags) > 0 {
		for _, tag := range req.Tags {
			k.Db.SaveTag(key, tag)
		}
	}

	//----------------------------

	response := &awskms.CreateKeyOutput{
		KeyMetadata: key.GetMetadata(),
	}

	return response, nil
}

func (k KmsService) CreateKeyFromSeed(req awskms.CreateKeyInput) (cmk.Key, error) {
	// We'll use the standard method of creating the key, then replace the key's material with that from the seed.

	return nil, nil
}
