package handler

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/nsmithuk/local-kms/src/cmk"
)

// Using custom struct to be able to decode ValidTo
// as simple Int64. Alternative would be custom
// type and marshal/unmarshal functions (again not
// possible using the type from the AWS library)
type ImportKeyMaterialInput struct {
	KeyId                *string
	ImportToken          []byte
	EncryptedKeyMaterial []byte
	ExpirationModel      *string
	// We override this from
	// ValidTo *time.Time `type:"timestamp"`
	// as json.Decode doesn't like epochs
	ValidTo *int64
}

func (r *RequestHandler) ImportKeyMaterial() Response {
	var body *ImportKeyMaterialInput
	if err := r.decodeBodyInto(&body); err != nil {
		r.logger.Errorf("Error decoding ImportKeyMaterialInput. Err %s\n", err.Error())
		body = &ImportKeyMaterialInput{}
	}

	//--------------------------------
	// Validation

	if body.KeyId == nil {
		msg := "KeyId is a required parameter"

		r.logger.Warn(msg)
		return NewMissingParameterResponse(msg)
	}

	if body.ImportToken == nil {
		msg := "ImportToken is a required parameter"

		r.logger.Warnf(msg)
		return NewMissingParameterResponse(msg)
	}

	if body.EncryptedKeyMaterial == nil {
		msg := "EncryptedKeyMaterial is a required parameter"

		r.logger.Warn(msg)
		return NewMissingParameterResponse(msg)
	}

	var expirationModel cmk.ExpirationModel
	switch *body.ExpirationModel {
	case "KEY_MATERIAL_EXPIRES", "KEY_MATERIAL_DOES_NOT_EXPIRE":
		expirationModel = cmk.ExpirationModel(*body.ExpirationModel)

	default:
		msg := fmt.Sprintf("1 validation error detected: Value '%s' at 'expirationModel' failed to satisfy constraint: Member must satisfy enum value set: [KEY_MATERIAL_DOES_NOT_EXPIRE, KEY_MATERIAL_EXPIRES]", *body.ExpirationModel)

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg)
	}

	if expirationModel == cmk.ExpirationModelKeyMaterialExpires && body.ValidTo == nil {
		msg := "A validTo date must be set if the ExpirationModel is KEY_MATERIAL_EXPIRES"

		r.logger.Warn(msg)
		return NewValidationExceptionResponse(msg)
	}

	// TODO: AWS does actually check the size of the encrypted data to ensure it matches the wrapping algorithm
	// An error occurred (ValidationException) when calling the ImportKeyMaterial operation: Invalid encrypted key size.

	if body.ValidTo != nil && *body.ValidTo <= time.Now().Unix() {
		msg := "ValidTo must be in the future"

		r.logger.Warn(msg)
		return NewValidationExceptionResponse(msg)
	}

	key, response := r.getKey(*body.KeyId)
	if !response.Empty() {
		return response
	}

	if key == nil {
		msg := fmt.Sprintf("Key '%s' does not exist", key.GetArn())

		r.logger.Warnf(msg)
		return NewNotFoundExceptionResponse(msg)
	}

	keyMetadata := key.GetMetadata()
	if keyMetadata.Origin != cmk.KeyOriginExternal {
		msg := fmt.Sprintf("%s origin is %s which is not valid for this operation.", key.GetArn(), keyMetadata.Origin)

		r.logger.Warnf(msg)
		return NewUnsupportedOperationException(msg)
	}

	switch keyMetadata.KeyState {
	case cmk.KeyStatePendingDeletion:
		msg := fmt.Sprintf("%s is pending deletion.", *body.KeyId)

		r.logger.Warnf(msg)
		return NewKMSInvalidStateExceptionResponse(msg)

	case cmk.KeyStateUnavailable:
		msg := fmt.Sprintf("%s is unavailable.", *body.KeyId)

		r.logger.Warnf(msg)
		return NewKMSInvalidStateExceptionResponse(msg)
	}

	params := key.(*cmk.AesKey).GetParametersForImport()
	if params == nil || !bytes.Equal(params.ImportToken, body.ImportToken) {

		r.logger.Warnf("Invalid import token when when calling the ImportKeyMaterial operation for key %s.", key.GetArn())
		return NewInvalidImportTokenExceptionResponse()
	}

	if params.ParametersValidTo < time.Now().Unix() {
		msg := fmt.Sprintf("Parameters for key material import have expired. Key '%s'", key.GetArn())

		r.logger.Warnf(msg)
		return NewExpiredImportTokenExceptionResponse()
	}

	// Attempt to decrypt the encyrpted key material
	var decrypterOps crypto.DecrypterOpts
	switch params.WrappingAlgorithm {
	case cmk.WrappingAlgorithmOaepSha1:
		decrypterOps = &rsa.OAEPOptions{Hash: crypto.SHA1}
	case cmk.WrappingAlgorithmOaepSh256:
		decrypterOps = &rsa.OAEPOptions{Hash: crypto.SHA256}
	case cmk.WrappingAlgorithmPkcs1V15:
		decrypterOps = &rsa.PKCS1v15DecryptOptions{}
	}

	keyMaterial, err := params.PrivateKey.Decrypt(rand.Reader, body.EncryptedKeyMaterial, decrypterOps)
	if err != nil {
		msg := fmt.Sprintf("Unable to decode EncryptedKeyMaterial: %s", err.Error())

		r.logger.Warnf(msg)
		return NewInvalidCiphertextExceptionResponse("")
	}

	if err = key.(*cmk.AesKey).ImportKeyMaterial(keyMaterial); err != nil {
		msg := fmt.Sprintf("Unable to import key material: %s", err.Error())

		r.logger.Warnf(msg)
		return NewIncorrectKeyMaterialExceptionResponse()
	}

	keyMetadata.ExpirationModel = expirationModel
	keyMetadata.KeyState = cmk.KeyStateEnabled
	keyMetadata.Enabled = true

	if expirationModel == cmk.ExpirationModelKeyMaterialExpires {
		keyMetadata.ValidTo = *body.ValidTo
	} else {
		keyMetadata.ValidTo = 0
	}

	//--------------------------------
	// Save the key

	if err = r.database.SaveKey(key); err != nil {
		r.logger.Error(err)
		return NewInternalFailureExceptionResponse(err.Error())
	}

	r.logger.Infof("Imported key material for key %s", key.GetArn())

	return NewResponse(200, nil)
}
