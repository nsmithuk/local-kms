package kms

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/nsmithuk/local-kms/internal/kms/cmk"
	"github.com/nsmithuk/local-kms/internal/kms/cmk/x509ecc"
	"github.com/nsmithuk/local-kms/internal/kms/data"
	"github.com/nsmithuk/local-kms/internal/kms/kmserr"
	"github.com/nsmithuk/local-kms/internal/kms/validation"
)

func (k KmsService) GenerateDataKeyPairWithoutPlaintext(ctx context.Context, req awskms.GenerateDataKeyPairWithoutPlaintextInput) (*awskms.GenerateDataKeyPairWithoutPlaintextOutput, []error) {
	dataKey, errs := k.GenerateDataKeyPair(ctx, awskms.GenerateDataKeyPairInput{
		KeyId:             req.KeyId,
		EncryptionContext: req.EncryptionContext,
		KeyPairSpec:       req.KeyPairSpec,
	})
	if errs != nil {
		return nil, errs
	}

	return &awskms.GenerateDataKeyPairWithoutPlaintextOutput{
		KeyId:                    dataKey.KeyId,
		KeyMaterialId:            dataKey.KeyMaterialId,
		KeyPairSpec:              req.KeyPairSpec,
		PublicKey:                dataKey.PublicKey,
		PrivateKeyCiphertextBlob: dataKey.PrivateKeyCiphertextBlob,
	}, nil
}

func (k KmsService) GenerateDataKeyPair(ctx context.Context, req awskms.GenerateDataKeyPairInput) (*awskms.GenerateDataKeyPairOutput, []error) {

	validationErrors := make([]error, 0)

	keyId, err := k.ResolveKeyArn(req.KeyId)
	if err != nil {
		validationErrors = append(validationErrors, err)
	}

	//---

	err = validation.KeyPairSpec(req.KeyPairSpec)
	if err != nil {
		validationErrors = append(validationErrors, err)
	}

	if len(validationErrors) > 0 {
		return nil, validationErrors
	}

	//---

	key, err := k.Db.LoadKey(keyId)
	if err != nil {
		if errors.Is(err, data.ErrKeyNotFound) {
			return nil, []error{
				kmserr.NewValidation(kmserr.CauseNotFoundException, "A key with the arn %s does not exists", keyId),
			}
		}
		return nil, []error{err}
	}

	if key.GetKeyType() != cmk.TypeSymmetricKey {
		return nil, []error{
			fmt.Errorf("keyspec must be %s", types.KeySpecSymmetricDefault),
		}
	}

	//---

	var publicKey []byte
	var privateKey []byte

	switch req.KeyPairSpec {
	case types.DataKeyPairSpecRsa2048, types.DataKeyPairSpecRsa3072, types.DataKeyPairSpecRsa4096:
		var bits int

		switch req.KeyPairSpec {
		case types.DataKeyPairSpecRsa2048:
			bits = 2048
		case types.DataKeyPairSpecRsa3072:
			bits = 3072
		case types.DataKeyPairSpecRsa4096:
			bits = 4096
		}

		rsaKey, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, []error{err}
		}

		privateKey, err = x509.MarshalPKCS8PrivateKey(rsaKey)
		if err != nil {
			return nil, []error{err}
		}

		publicKey, err = x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
		if err != nil {
			return nil, []error{err}
		}
	case types.DataKeyPairSpecEccNistP256, types.DataKeyPairSpecEccNistP384, types.DataKeyPairSpecEccNistP521, types.DataKeyPairSpecEccSecgP256k1:
		var curve elliptic.Curve
		switch req.KeyPairSpec {
		case types.DataKeyPairSpecEccNistP256:
			curve = elliptic.P256()
		case types.DataKeyPairSpecEccNistP384:
			curve = elliptic.P384()
		case types.DataKeyPairSpecEccNistP521:
			curve = elliptic.P521()
		case types.DataKeyPairSpecEccSecgP256k1:
			curve = secp256k1.S256()
		}

		ecdsaKey, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, []error{err}
		}

		publicKey, err = x509ecc.MarshalPKIXPublicKey(&ecdsaKey.PublicKey)
		if err != nil {
			return nil, []error{err}
		}

		privateKey, err = x509ecc.MarshalPKCS8PrivateKey(ecdsaKey)
		if err != nil {
			return nil, []error{err}
		}
	case types.DataKeyPairSpecEccNistEdwards25519:
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			return nil, []error{err}
		}

		privateKey, err = x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, []error{err}
		}

		publicKey, err = x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return nil, []error{err}
		}
	}

	//---

	encrypt, errs := k.Encrypt(ctx, awskms.EncryptInput{
		KeyId:               aws.String(key.GetArn()),
		Plaintext:           privateKey,
		EncryptionAlgorithm: types.EncryptionAlgorithmSpecSymmetricDefault,
		EncryptionContext:   req.EncryptionContext,
	})
	if errs != nil {
		return nil, errs
	}

	return &awskms.GenerateDataKeyPairOutput{
		KeyId:                    encrypt.KeyId,
		KeyMaterialId:            key.GetMetadata().CurrentKeyMaterialId,
		KeyPairSpec:              req.KeyPairSpec,
		PublicKey:                publicKey,
		PrivateKeyPlaintext:      privateKey,
		PrivateKeyCiphertextBlob: encrypt.CiphertextBlob,
	}, nil
}
