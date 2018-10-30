package handler

import(
	"github.com/NSmithUK/local-kms-go/src/service"
	"github.com/NSmithUK/local-kms-go/src/config"
	"github.com/NSmithUK/local-kms-go/src/data"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/satori/go.uuid"
	"time"
)

func (r *RequestHandler) CreateKey() Response {

	var body *kms.CreateKeyInput

	r.decodeBodyInto(&body)

	//--------------------------------
	// Validation



	//--------------------------------
	// Create the key set up

	keyId := uuid.NewV4().String()

	key := &data.Key{
		Metadata: data.KeyMetadata{
			Arn: config.ArnPrefix() + "key/" + keyId,
			KeyId: keyId,
			AWSAccountId: config.AWSAccountId,
			CreationDate: time.Now().UnixNano(),
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

	err := r.database.SaveKey(key)
	if err != nil {
		r.logger.Error(err)
	}

	//---

	response := map[string]data.KeyMetadata{
		"KeyMetadata": key.Metadata,
	}

	return NewResponse( 200, response)
}
