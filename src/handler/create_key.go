package handler

import(
	"github.com/NSmithUK/local-kms-go/src/service"
	"github.com/NSmithUK/local-kms-go/src/config"
	"github.com/NSmithUK/local-kms-go/src/data"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/satori/go.uuid"
	"time"
	"fmt"
)

func (r *RequestHandler) CreateKey() Response {

	var body *kms.CreateKeyInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.CreateKeyInput{}
	}

	//--------------------------------
	// Validation

	if body.Description != nil && len(*body.Description) > 2 {
		msg := fmt.Sprintf("1 validation error detected: Value '%s' at 'description' failed to satisfy " +
			"constraint: Member must have length less than or equal to 8192", *body.Description)

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg)
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

	//---

	response := map[string]data.KeyMetadata{
		"KeyMetadata": key.Metadata,
	}

	return NewResponse( 200, response)
}
