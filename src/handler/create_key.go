package handler

import (
	"fmt"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/nsmithuk/local-kms/src/config"
	"github.com/nsmithuk/local-kms/src/data"
	"github.com/nsmithuk/local-kms/src/service"
	"github.com/satori/go.uuid"
	"time"
)

func (r *RequestHandler) CreateKey() Response {

	var body *kms.CreateKeyInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.CreateKeyInput{}
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

	//----

	if body.Description == nil {
		empty := ""
		body.Description = &empty
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

	//--------------------------------
	// Create the key set up

	keyId := uuid.NewV4().String()

	key := &data.Key{
		Metadata: data.KeyMetadata{
			Arn: config.ArnPrefix() + "key/" + keyId,
			KeyId: keyId,
			AWSAccountId: config.AWSAccountId,
			CreationDate: time.Now().Unix(),
			Description: body.Description,
			Enabled: true,
			KeyManager: "CUSTOMER",
			KeyState: "Enabled",
			KeyUsage: "ENCRYPT_DECRYPT",
			Origin: "AWS_KMS",
		},

		// Add the first backing key
		BackingKeys: [][32]byte{ service.GenerateNewKey() },
	}


	//--------------------------------
	// Save the key

	err = r.database.SaveKey(key)
	if err != nil {
		r.logger.Error(err)
		return NewInternalFailureExceptionResponse(err.Error())
	}

	r.logger.Infof("New key created: %s\n", key.Metadata.Arn)

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

	return NewResponse( 200, map[string]data.KeyMetadata{
		"KeyMetadata": key.Metadata,
	})
}
