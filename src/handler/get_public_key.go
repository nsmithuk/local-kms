package handler

import (
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/ethereum/go-ethereum/crypto"
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

	var publicKey []byte

	switch k := key.(type) {
	case *cmk.RsaKey:

		publicKey, err = x509.MarshalPKIXPublicKey(&k.PrivateKey.PublicKey)
		if err != nil {
			return NewInternalFailureExceptionResponse(err.Error())
		}

	case *cmk.EccKey:

		privateKey := ecdsa.PrivateKey(k.PrivateKey)

		publicKey, err = x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if err != nil {
			return NewInternalFailureExceptionResponse(err.Error())
		}

	case *cmk.SecpEccKey:

		algo := asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
		type pkixPublicKey struct {
			Algo      pkix.AlgorithmIdentifier
			BitString asn1.BitString
		}

		pk := k.PrivateKey.PublicKey
		publicKeyBytes := crypto.FromECDSAPub(&pk)
		publicKey, err = asn1.Marshal(pkixPublicKey{
			Algo: pkix.AlgorithmIdentifier{
				Algorithm: algo,
				Parameters: asn1.RawValue{
					Class:      0,
					Tag:        6,
					IsCompound: false,
					Bytes:      []byte{0x2b, 0x81, 0x04, 0x00, 0x0a},
					FullBytes:  []byte{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a},
				},
			},
			BitString: asn1.BitString{
				Bytes:     publicKeyBytes,
				BitLength: 8 * len(publicKeyBytes),
			},
		})

		if err != nil {
			return NewInternalFailureExceptionResponse(err.Error())
		}

	default:
		r.logger.Warnf(fmt.Sprintf("Key '%s' does does not support returning a public key", key.GetArn()))
		return NewUnsupportedOperationException("")
	}

	//---

	return NewResponse(200, &struct {
		KeyId                 string
		CustomerMasterKeySpec cmk.CustomerMasterKeySpec
		//EncryptionAlgorithms	[]cmk.EncryptionAlgorithm
		SigningAlgorithms []cmk.SigningAlgorithm
		KeyUsage          cmk.KeyUsage
		PublicKey         []byte
	}{
		KeyId:                 key.GetArn(),
		CustomerMasterKeySpec: key.GetMetadata().CustomerMasterKeySpec,
		//EncryptionAlgorithms: key.GetMetadata().EncryptionAlgorithms,
		SigningAlgorithms: key.GetMetadata().SigningAlgorithms,
		KeyUsage:          key.GetMetadata().KeyUsage,
		PublicKey:         publicKey,
	})
}
