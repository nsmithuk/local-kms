package handler

import (
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/nsmithuk/local-kms/src/cmk"
	"github.com/nsmithuk/local-kms/src/config"
	"github.com/nsmithuk/local-kms/src/data"
	uuid "github.com/satori/go.uuid"
)

func (r *RequestHandler) CreateKey() Response {

	var body *kms.CreateKeyInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.CreateKeyInput{}
	}

	//---

	keyId := uuid.NewV4().String()

	metadata := cmk.KeyMetadata{
		Arn:          config.ArnPrefix() + "key/" + keyId,
		KeyId:        keyId,
		AWSAccountId: config.AWSAccountId,
		CreationDate: time.Now().Unix(),
		Enabled:      true,
		KeyManager:   "CUSTOMER",
		KeyState:     cmk.KeyStateEnabled,
		Origin:       cmk.KeyOriginAwsKms,
	}

	//--------------------------------
	// Validation

	if body.Description != nil && len(*body.Description) > 8192 {
		msg := fmt.Sprintf("1 validation error detected: Value '%s' at 'description' failed to satisfy "+
			"constraint: Member must have length less than or equal to 8192", *body.Description)

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg)
	}

	if body.Policy != nil && len(*body.Policy) > 32768 {
		msg := fmt.Sprintf("1 validation error detected: Value '%s' at 'policy' failed to satisfy "+
			"constraint: Member must have length less than or equal to 32768", *body.Policy)

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg)
	}

	response := r.validateTags(body.Tags)
	if !response.Empty() {
		return response
	}

	if body.Description != nil {
		metadata.Description = body.Description
	}

	if body.Policy == nil {
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
		}`, config.AWSAccountId)
		body.Policy = &policy
	}

	if body.CustomerMasterKeySpec == nil {
		sd := "SYMMETRIC_DEFAULT"
		body.CustomerMasterKeySpec = &sd
	}

	if body.Origin != nil {
		switch *body.Origin {
		case "AWS_KMS":
			// nop
		case "EXTERNAL":

			if *body.CustomerMasterKeySpec != "SYMMETRIC_DEFAULT" {
				msg := fmt.Sprintf("KeySpec %s is not supported for Origin %s", *body.CustomerMasterKeySpec, *body.Origin)

				r.logger.Warnf(msg)
				return NewValidationExceptionResponse(msg)
			}

			r.logger.Infof("Set key origin to %s and state to PendingImport", *body.Origin)
			metadata.Origin = cmk.KeyOrigin(*body.Origin)
			metadata.Enabled = false
			metadata.KeyState = cmk.KeyStatePendingImport

		case "AWS_CLOUDHSM":

			msg := fmt.Sprintf("Local KMS does not yet support Origin AWS_CLOUDHSM.")
			r.logger.Warnf(msg)
			return NewUnsupportedOperationException(msg)

		default:

			msg := fmt.Sprintf("1 validation error detected: Value '%s' at 'origin' failed to satisfy constraint: Member must satisfy enum value set: [EXTERNAL, AWS_CLOUDHSM, AWS_KMS]", *body.Origin)

			r.logger.Warnf(msg)
			return NewValidationExceptionResponse(msg)
		}
	}

	//---

	var key cmk.Key

	switch *body.CustomerMasterKeySpec {
	case "SYMMETRIC_DEFAULT":

		if body.KeyUsage != nil && *body.KeyUsage != "ENCRYPT_DECRYPT" {
			msg := fmt.Sprintf("The operation failed because the KeyUsage value of the CMK is %s. To perform this operation, the KeyUsage value must be ENCRYPT_DECRYPT.", *body.KeyUsage)
			r.logger.Warnf(msg)
			return NewValidationExceptionResponse(msg)
		}

		key = cmk.NewAesKey(metadata, *body.Policy, metadata.Origin)

	case "ECC_NIST_P256", "ECC_NIST_P384", "ECC_NIST_P521":

		if body.KeyUsage == nil {
			msg := fmt.Sprintf("You must specify a KeyUsage value for an asymmetric CMK.")
			r.logger.Warnf(msg)
			return NewValidationExceptionResponse(msg)
		}

		if *body.KeyUsage != "SIGN_VERIFY" {
			msg := fmt.Sprintf("KeyUsage ENCRYPT_DECRYPT is not compatible with KeySpec %s", *body.CustomerMasterKeySpec)
			r.logger.Warnf(msg)
			return NewValidationExceptionResponse(msg)
		}

		key, err = cmk.NewEccKey(cmk.CustomerMasterKeySpec(*body.CustomerMasterKeySpec), metadata, *body.Policy)
		if err != nil {
			r.logger.Error(err)
			return NewInternalFailureExceptionResponse(err.Error())
		}

	case "ECC_SECG_P256K1":
		if body.KeyUsage == nil {
			msg := fmt.Sprintf("You must specify a KeyUsage value for an asymmetric CMK.")
			r.logger.Warnf(msg)
			return NewValidationExceptionResponse(msg)
		}

		if *body.KeyUsage != "SIGN_VERIFY" {
			msg := fmt.Sprintf("KeyUsage ENCRYPT_DECRYPT is not compatible with KeySpec %s", *body.CustomerMasterKeySpec)
			r.logger.Warnf(msg)
			return NewValidationExceptionResponse(msg)
		}

		key, err = cmk.NewSecpEccKey(cmk.CustomerMasterKeySpec(*body.CustomerMasterKeySpec), metadata, *body.Policy)
		if err != nil {
			r.logger.Error(err)
			return NewInternalFailureExceptionResponse(err.Error())
		}

	case "RSA_2048", "RSA_3072", "RSA_4096":

		if body.KeyUsage == nil {
			msg := fmt.Sprintf("You must specify a KeyUsage value for an asymmetric CMK.")
			r.logger.Warnf(msg)
			return NewValidationExceptionResponse(msg)
		}

		if !(*body.KeyUsage == "SIGN_VERIFY" || *body.KeyUsage == "ENCRYPT_DECRYPT") {
			msg := fmt.Sprintf("KeyUsage %s is not compatible with KeySpec %s", *body.KeyUsage, *body.CustomerMasterKeySpec)
			r.logger.Warnf(msg)
			return NewValidationExceptionResponse(msg)
		}

		key, err = cmk.NewRsaKey(cmk.CustomerMasterKeySpec(*body.CustomerMasterKeySpec), cmk.KeyUsage(*body.KeyUsage), metadata, *body.Policy)
		if err != nil {
			r.logger.Error(err)
			return NewInternalFailureExceptionResponse(err.Error())
		}

	default:

		msg := fmt.Sprintf("1 validation error detected: Value '%s' at 'customerMasterKeySpec' "+
			"failed to satisfy constraint: Member must satisfy enum value set: [RSA_2048, ECC_NIST_P384, "+
			"ECC_NIST_P256, ECC_NIST_P521, RSA_3072, ECC_SECG_P256K1, RSA_4096, SYMMETRIC_DEFAULT]", *body.CustomerMasterKeySpec)

		r.logger.Warnf(msg)

		return NewValidationExceptionResponse(msg)
	}

	//--------------------------------
	// Save the key

	err = r.database.SaveKey(key)
	if err != nil {
		r.logger.Error(err)
		return NewInternalFailureExceptionResponse(err.Error())
	}

	r.logger.Infof("New key created: %s\n", key.GetArn())

	//--------------------------------
	// Create the tags

	if body.Tags != nil && len(body.Tags) > 0 {
		for _, kv := range body.Tags {
			t := &data.Tag{
				TagKey:   *kv.TagKey,
				TagValue: *kv.TagValue,
			}
			_ = r.database.SaveTag(key, t)

			r.logger.Infof("New tag created: %s / %s\n", t.TagKey, t.TagValue)
		}
	}

	//---

	return NewResponse(200, map[string]*cmk.KeyMetadata{
		"KeyMetadata": key.GetMetadata(),
	})
}
