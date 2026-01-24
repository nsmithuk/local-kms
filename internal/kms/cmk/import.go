package cmk

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/nsmithuk/local-kms/internal/kms/cmk/wrapping"
)

type ParametersForImport struct {
	ParametersValidTo time.Time
	ImportToken       []byte
	PrivateKey        rsa.PrivateKey
	WrappingAlgorithm types.AlgorithmSpec
}

func (p *ParametersForImport) UnwrapKeyMaterial(ciphertext []byte) ([]byte, error) {

	switch p.WrappingAlgorithm {
	case types.AlgorithmSpecRsaAesKeyWrapSha1:
		return p.unwrapAesKeyMaterial(ciphertext, &rsa.OAEPOptions{Hash: crypto.SHA1})
	case types.AlgorithmSpecRsaAesKeyWrapSha256:
		return p.unwrapAesKeyMaterial(ciphertext, &rsa.OAEPOptions{Hash: crypto.SHA256})
	case types.AlgorithmSpecRsaesOaepSha1:
		return p.PrivateKey.Decrypt(rand.Reader, ciphertext, &rsa.OAEPOptions{Hash: crypto.SHA1})
	case types.AlgorithmSpecRsaesOaepSha256:
		return p.PrivateKey.Decrypt(rand.Reader, ciphertext, &rsa.OAEPOptions{Hash: crypto.SHA256})
	case types.AlgorithmSpecRsaesPkcs1V15:
		return p.PrivateKey.Decrypt(rand.Reader, ciphertext, &rsa.PKCS1v15DecryptOptions{})
	}

	return nil, fmt.Errorf("unsupported wrappingAlgorithm: %s", p.WrappingAlgorithm)
}

func (p *ParametersForImport) unwrapAesKeyMaterial(ciphertext []byte, decrypterOps crypto.DecrypterOpts) ([]byte, error) {
	rsaKeyBytes := p.PrivateKey.Size()
	if len(ciphertext) <= rsaKeyBytes {
		return nil, errors.New("ciphertext too short")
	}

	encryptedKEK := ciphertext[:rsaKeyBytes]
	wrappedKeyMaterial := ciphertext[rsaKeyBytes:]

	//---

	// Unencrypted KEK
	kek, err := p.PrivateKey.Decrypt(rand.Reader, encryptedKEK, decrypterOps)
	if err != nil {
		return nil, err
	}

	//---

	if len(kek) != 32 {
		return nil, fmt.Errorf("invalid KEK length: %d. Keys must be 256 bit", len(kek))
	}

	// Unwraps and decrypts
	plaintext, err := wrapping.AesKeyUnwrapWithPadding(kek, wrappedKeyMaterial)
	if err != nil {
		return nil, fmt.Errorf("unwrap key material: %w", err)
	}

	return plaintext, nil
}
