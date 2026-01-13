package cmk

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/nsmithuk/local-kms/internal/kms/cmk/x509ecc"
)

type ecdsaSignature struct {
	R, S *big.Int
}

//---------------------------------------------
// Operation functions

func (k *EcdsaKey) GetPublicKey() ([]byte, error) {
	return x509ecc.MarshalPKIXPublicKey(&k.PrivateKey.PublicKey)
}

//---------------------------------------------

func (k *EcdsaKey) prepSigningDigest(message []byte, algorithm types.SigningAlgorithmSpec, messageType types.MessageType) ([]byte, error) {
	digest := message

	if messageType == types.MessageTypeRaw {
		var err error
		digest, err = hashMessage(message, algorithm)
		if err != nil {
			return nil, err
		}
	}

	//---

	var err error

	switch algorithm {
	case types.SigningAlgorithmSpecEcdsaSha256:
		if len(digest) != (256 / 8) {
			err = fmt.Errorf("invalid signature digest length %d for algorithm %s", len(digest), algorithm)
		}
	case types.SigningAlgorithmSpecEcdsaSha384:
		if len(digest) != (384 / 8) {
			err = fmt.Errorf("invalid signature digest length %d for algorithm %s", len(digest), algorithm)
		}
	case types.SigningAlgorithmSpecEcdsaSha512:
		if len(digest) != (512 / 8) {
			err = fmt.Errorf("invalid signature digest length %d for algorithm %s", len(digest), algorithm)
		}
	default:
		err = fmt.Errorf("unsupported signing algorithm %v", algorithm)
	}

	return digest, err
}

func (k *EcdsaKey) Sign(message []byte, algorithm types.SigningAlgorithmSpec, messageType types.MessageType) ([]byte, error) {
	if err := k.enforceKeyUsageType(types.KeyUsageTypeSignVerify); err != nil {
		return nil, err
	}

	digest, err := k.prepSigningDigest(message, algorithm, messageType)

	//---

	key := ecdsa.PrivateKey(k.PrivateKey)

	r, s, err := ecdsa.Sign(rand.Reader, &key, digest)
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(ecdsaSignature{r, s})

}

func (k *EcdsaKey) Verify(message []byte, algorithm types.SigningAlgorithmSpec, messageType types.MessageType, signature []byte) (bool, error) {
	if err := k.enforceKeyUsageType(types.KeyUsageTypeSignVerify); err != nil {
		return false, err
	}

	sig := ecdsaSignature{}

	_, err := asn1.Unmarshal(signature, &sig)
	if err != nil {
		// An error here mean the signature cannot be valid.
		return false, nil
	}

	//---

	digest, err := k.prepSigningDigest(message, algorithm, messageType)

	//---

	key := ecdsa.PrivateKey(k.PrivateKey).PublicKey

	valid := ecdsa.Verify(&key, digest, sig.R, sig.S)

	return valid, nil
}

func (k *EcdsaKey) DeriveSharedSecret(peerPublicKey []byte, algorithm types.KeyAgreementAlgorithmSpec) ([]byte, error) {
	if err := k.enforceKeyUsageType(types.KeyUsageTypeKeyAgreement); err != nil {
		return nil, err
	}

	if algorithm != types.KeyAgreementAlgorithmSpecEcdh {
		return nil, fmt.Errorf("KeyAgreementAlgorithm spec '%s' is not supported", algorithm)
	}

	pubKey, err := x509ecc.ParsePKIXPublicKey(peerPublicKey)
	if err != nil {
		return nil, err
	}

	//---

	priKey := ecdsa.PrivateKey(k.PrivateKey)

	//---

	if pubKey.Curve == nil || priKey.Curve == nil {
		return nil, errors.New("missing curve parameters")
	}
	if pubKey.Curve.Params().Name != pubKey.Curve.Params().Name {
		return nil, errors.New("curve mismatch")
	}
	if !priKey.Curve.IsOnCurve(pubKey.X, pubKey.Y) {
		return nil, errors.New("peer public key is not on curve")
	}

	//---

	sk, err := priKey.ECDH()
	if err != nil {
		return nil, err
	}

	pk, err := pubKey.ECDH()
	if err != nil {
		return nil, err
	}

	//---

	secret, err := sk.ECDH(pk)
	if err != nil {
		return nil, fmt.Errorf("ecdh failed: %w", err)
	}
	return secret, nil
}
