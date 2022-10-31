package handler

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/btcsuite/btcd/btcec"

	"github.com/nsmithuk/local-kms/src/cmk"
	"github.com/nsmithuk/local-kms/src/x509"
)

type GenerateDataKeyPairResponse struct {
	KeyId                    string
	KeyPairSpec              string
	PrivateKeyCiphertextBlob []byte
	PrivateKeyPlaintext      []byte `json:",omitempty"`
	PublicKey                []byte
}

func (r *RequestHandler) GenerateDataKeyPair() Response {
	errResponse, keyResponse := r.generateDataKeyPair()

	if !errResponse.Empty() {
		return errResponse
	}

	//---

	r.logger.Infof("Data key pair generated with plaintext: %s\n", keyResponse.KeyId)

	return NewResponse(200, keyResponse)
}

func (r *RequestHandler) generateDataKeyPair() (Response, *GenerateDataKeyPairResponse) {

	var body *kms.GenerateDataKeyPairInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.GenerateDataKeyPairInput{}
	}

	//--------------------------------
	// Validation

	if body.KeyId == nil {
		msg := "KeyId is a required parameter"

		r.logger.Warnf(msg)
		return NewMissingParameterResponse(msg), nil
	}

	if body.KeyPairSpec == nil {
		msg := "1 validation error detected: KeyPairSpec is required."

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg), nil
	}

	//----------------------------------

	key, response := r.getUsableKey(*body.KeyId)

	// If the response is not empty, there was an error
	if !response.Empty() {
		return response, nil
	}

	//----------------------------------

	keyPairSpec := cmk.KeySpec(*body.KeyPairSpec)

	var publicKey interface{}
	var privateKey interface{}
	//var err error

	switch keyPairSpec {
	case cmk.SpecEccNistP256:
		fallthrough
	case cmk.SpecEccNistP384:
		fallthrough
	case cmk.SpecEccNistP521:
		fallthrough
	case cmk.SpecEccSecp256k1:

		var curve elliptic.Curve
		switch keyPairSpec {
		case cmk.SpecEccNistP256:
			curve = elliptic.P256()
		case cmk.SpecEccNistP384:
			curve = elliptic.P384()
		case cmk.SpecEccNistP521:
			curve = elliptic.P521()
		case cmk.SpecEccSecp256k1:
			curve = btcec.S256()
		}

		k, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return NewInternalFailureExceptionResponse(err.Error()), nil
		}

		privateKey = k
		publicKey = &k.PublicKey

	case cmk.SpecRsa2048:
		fallthrough
	case cmk.SpecRsa3072:
		fallthrough
	case cmk.SpecRsa4096:

		var bits int
		switch keyPairSpec {
		case cmk.SpecRsa2048:
			bits = 2048
		case cmk.SpecRsa3072:
			bits = 3072
		case cmk.SpecRsa4096:
			bits = 4096
		}

		k, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return NewInternalFailureExceptionResponse(err.Error()), nil
		}

		privateKey = k
		publicKey = &k.PublicKey

	default:
		msg := "1 validation error detected: KeyPairSpec is invalid."
		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg), nil
	}

	public, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return NewInternalFailureExceptionResponse(err.Error()), nil
	}

	private, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return NewInternalFailureExceptionResponse(err.Error()), nil
	}

	//---

	var cipherResponse []byte

	switch k := key.(type) {
	case *cmk.AesKey:

		cipherResponse, err = k.EncryptAndPackage(private, body.EncryptionContext)
		if err != nil {
			r.logger.Error(err.Error())
			return NewInternalFailureExceptionResponse(err.Error()), nil
		}

	default:

		if k.GetMetadata().KeyUsage == cmk.UsageSignVerify {
			msg := fmt.Sprintf("%s key usage is %s which is not valid for GenerateDataKeyPair.", k.GetArn(), k.GetMetadata().KeyUsage)
			r.logger.Warnf(msg)
			return NewInvalidKeyUsageException(msg), nil
		}

		msg := fmt.Sprintf("%s key KeySpec is %s which is not valid for GenerateDataKeyPair.", k.GetArn(), k.GetMetadata().CustomerMasterKeySpec)
		r.logger.Warnf(msg)
		return NewInvalidKeyUsageException(msg), nil
	}

	//---

	return Response{}, &GenerateDataKeyPairResponse{
		KeyId:                    key.GetArn(),
		KeyPairSpec:              string(keyPairSpec),
		PrivateKeyCiphertextBlob: cipherResponse,
		PrivateKeyPlaintext:      private,
		PublicKey:                public,
	}
}
