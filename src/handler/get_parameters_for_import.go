package handler

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/nsmithuk/local-kms/src/cmk"
	"github.com/nsmithuk/local-kms/src/service"
)

type ParametersForImportResponse struct {
	KeyId             string
	ParametersValidTo int64
	ImportToken       string
	PublicKey         string
}

func (r *RequestHandler) GetParametersForImport() Response {

	var body *kms.GetParametersForImportInput
	if err := r.decodeBodyInto(&body); err != nil {
		r.logger.Errorf("Error decoding GetParametersForImportInput. Err %s\n", err.Error())
		body = &kms.GetParametersForImportInput{}
	}

	//--------------------------------
	// Validation

	if body.KeyId == nil {
		msg := "KeyId is a required parameter"

		r.logger.Warnf(msg)
		return NewMissingParameterResponse(msg)
	}

	if body.WrappingAlgorithm == nil {
		msg := "WrappingAlgorithm is a required parameter"

		r.logger.Warnf(msg)
		return NewMissingParameterResponse(msg)
	}

	var wrappingAlgorithm cmk.WrappingAlgorithm
	switch *body.WrappingAlgorithm {
	case "RSAES_PKCS1_V1_5", "RSAES_OAEP_SHA_1", "RSAES_OAEP_SHA_256":
		wrappingAlgorithm = cmk.WrappingAlgorithm(*body.WrappingAlgorithm)

	default:
		msg := fmt.Sprintf("1 validation error detected: Value '%s' at 'wrappingAlgorithm' failed to satisfy constraint: Member must satisfy enum value set: [RSAES_OAEP_SHA_1, RSAES_OAEP_SHA_256, RSAES_PKCS1_V1_5]", *body.WrappingAlgorithm)

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg)
	}

	if body.WrappingKeySpec == nil {
		msg := "WrappingKeySpec is a required parameter"

		r.logger.Warnf(msg)
		return NewMissingParameterResponse(msg)
	}

	// If wrapping key ever starts accepting additional values then we'll need to adjust this
	var bits = 2048
	if strings.Compare(*body.WrappingKeySpec, "RSA_2048") != 0 {
		msg := fmt.Sprintf("1 validation error detected: Value '%s' at 'wrappingKeySpec' failed to satisfy constraint: Member must satisfy enum value set: [RSA_2048]", *body.WrappingKeySpec)

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg)
	}

	// //---

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
	if keyMetadata.Origin != "EXTERNAL" {
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

	// Create and save the parameters for key material import

	// Starting by generating a wrapping RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		msg := fmt.Sprintf("Failed to generate RSA key. Err: %s", err.Error())
		r.logger.Error(msg)
		return NewResponse(500, msg)
	}

	// public key
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		msg := fmt.Sprintf("Failed to get bytes for RSA public key. Err: %s", err.Error())
		r.logger.Error(msg)
		return NewResponse(500, msg)
	}

	// For import token we just generate a random base64 string that matches the length requirements that would be returned by AWS
	// Parameters are valid for 24 hours as per AWS
	params := &cmk.ParametersForImport{
		ImportToken:       service.GenerateRandomData(256),
		ParametersValidTo: time.Now().Add(24 * time.Duration(time.Hour)).Unix(),
		PrivateKey:        *rsaKey,
		WrappingAlgorithm: wrappingAlgorithm,
	}

	// Note - this is guaranteed to be an AesKey by virtue of the `EXTERNAL` origin
	key.(*cmk.AesKey).SetParametersForImport(params)

	//--------------------------------
	// Save the key

	if err := r.database.SaveKey(key); err != nil {
		r.logger.Error(err)
		return NewInternalFailureExceptionResponse(err.Error())
	}

	r.logger.Infof("Parameters for key material import created for key %s", key.GetArn())

	return NewResponse(200, &ParametersForImportResponse{
		KeyId:             key.GetArn(),
		ImportToken:       base64.StdEncoding.EncodeToString(params.ImportToken),
		ParametersValidTo: params.ParametersValidTo,
		PublicKey:         base64.StdEncoding.EncodeToString(pubKeyBytes),
	})
}
