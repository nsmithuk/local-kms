package handler

import (
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/nsmithuk/local-kms/src/cmk"
)

func (r *RequestHandler) GetPublicKey() Response {

	var body *kms.GetPublicKeyInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.GetPublicKeyInput{}
	}

	//--------------------------------
	// Validation

	if body.KeyId == nil {
		msg := "1 validation error detected: Value null at 'keyId' failed to satisfy constraint: Member must not be null"

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg)
	}

	//---

	key, response := r.getUsableKey(*body.KeyId)

	// If the response is not empty, there was an error
	if !response.Empty() {
		return response
	}

	//---

	// Check the key is ECC.
	if _,ok := key.(*cmk.EccKey); !ok {
		r.logger.Warnf(fmt.Sprintf("Key '%s' does does not support returning a public key", key.GetArn()))
		return NewUnsupportedOperationException("")
	}

	//---

	k1 := key.(*cmk.EccKey)
	k2 := ecdsa.PrivateKey(k1.PrivateKey)

	publicKey, err := x509.MarshalPKIXPublicKey(&k2.PublicKey)
	if err != nil {
		return NewInternalFailureExceptionResponse(err.Error())
	}

	//---

	return NewResponse( 200, &struct {
		KeyId					string
		CustomerMasterKeySpec	cmk.CustomerMasterKeySpec
		//EncryptionAlgorithms	[]cmk.EncryptionAlgorithm
		SigningAlgorithms		[]cmk.SigningAlgorithm
		KeyUsage				cmk.KeyUsage
		PublicKey				[]byte
	}{
		KeyId: key.GetArn(),
		CustomerMasterKeySpec: key.GetMetadata().CustomerMasterKeySpec,
		//EncryptionAlgorithms: key.GetMetadata().EncryptionAlgorithms,
		SigningAlgorithms: key.GetMetadata().SigningAlgorithms,
		KeyUsage: key.GetMetadata().KeyUsage,
		PublicKey: publicKey,
	})
}
