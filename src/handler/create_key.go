package handler

import (
	"fmt"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/nsmithuk/local-kms/src/cmk"
	"github.com/nsmithuk/local-kms/src/config"
	"github.com/nsmithuk/local-kms/src/data"
	"github.com/satori/go.uuid"
	"time"
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
		Arn:                   config.ArnPrefix() + "key/" + keyId,
		KeyId:                 keyId,
		AWSAccountId:          config.AWSAccountId,
		CreationDate:          time.Now().Unix(),
		Enabled:               true,
		KeyManager:            "CUSTOMER",
		KeyState:              "Enabled",
		Origin:                "AWS_KMS",
	}

	//--------------------------------
	// Validation

	if body.Description != nil && len(*body.Description) > 8192 {
		msg := fmt.Sprintf("1 validation error detected: Value '%s' at 'description' failed to satisfy " +
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

	//---

	var key cmk.Key

	switch *body.CustomerMasterKeySpec {
	case "SYMMETRIC_DEFAULT":

		if body.KeyUsage != nil && *body.KeyUsage == "SIGN_VERIFY" {
			msg := fmt.Sprintf("KeyUsage SIGN_VERIFY is not compatible with KeySpec SYMMETRIC_DEFAULT")
			r.logger.Warnf(msg)
			return NewValidationExceptionResponse(msg)
		}

		key = cmk.NewAesKey(metadata, *body.Policy)

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

		msg := fmt.Sprintf("Local KMS does not yet support ECC_SECG_P256K1 keys. Symmetric keys and ECC_NIST_* keys are supported.")
		r.logger.Warnf(msg)
		return NewUnsupportedOperationException(msg)

	case "RSA_2048", "RSA_3072", "RSA_4096":

		if body.KeyUsage == nil {
			msg := fmt.Sprintf("You must specify a KeyUsage value for an asymmetric CMK.")
			r.logger.Warnf(msg)
			return NewValidationExceptionResponse(msg)
		}

		if *body.KeyUsage != "SIGN_VERIFY" {
			msg := fmt.Sprintf("Local KMS currently only supports SIGN_VERIFY for RSA keys. ENCRYPT_DECRYPT is on the roadmap.")
			r.logger.Warnf(msg)
			return NewUnsupportedOperationException(msg)
		}

		key, err = cmk.NewRsaKey(cmk.CustomerMasterKeySpec(*body.CustomerMasterKeySpec), cmk.KeyUsage(*body.KeyUsage), metadata, *body.Policy)
		if err != nil {
			r.logger.Error(err)
			return NewInternalFailureExceptionResponse(err.Error())
		}

	default:

		msg := fmt.Sprintf("1 validation error detected: Value '%s' at 'customerMasterKeySpec' " +
			"failed to satisfy constraint: Member must satisfy enum value set: [RSA_2048, ECC_NIST_P384, " +
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

	return NewResponse( 200, map[string]*cmk.KeyMetadata{
		"KeyMetadata": key.GetMetadata(),
	})
}
