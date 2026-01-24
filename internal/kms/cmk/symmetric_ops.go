package cmk

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type CiphertextBlob []byte

/*
Wire format:
A) ArnLen        : 1 byte  (0..255)
B) MaterialIdLen : 1 byte  (0..255)
C) Arn           : ArnLen bytes
D) MaterialId    : MaterialIdLen bytes
E) Ciphertext    : remaining bytes
*/
func NewCiphertextBlob(keyArn string, ciphertext []byte, materialId string) []byte {
	arnBytes := []byte(keyArn)
	materialIdBytes := []byte(materialId)

	if len(arnBytes) > 255 {
		panic("kms: ARN too long")
	}
	if len(materialIdBytes) > 255 {
		panic("kms: MaterialID too long")
	}

	result := make([]byte, 0, 2+len(arnBytes)+len(materialIdBytes)+len(ciphertext))

	result = append(result, byte(len(arnBytes)))
	result = append(result, byte(len(materialIdBytes)))
	result = append(result, arnBytes...)
	result = append(result, materialIdBytes...)
	result = append(result, ciphertext...)

	return result
}

func (c CiphertextBlob) validate() (arnLen int, matLen int, ciphertextOffset int, err error) {
	if len(c) < 2 {
		return 0, 0, 0, fmt.Errorf("ciphertext blob too short: %d (need at least 2)", len(c))
	}

	arnLen = int(c[0])
	matLen = int(c[1])

	ciphertextOffset = 2 + arnLen + matLen
	if ciphertextOffset > len(c) {
		return 0, 0, 0, fmt.Errorf(
			"invalid lengths: arnLen=%d matLen=%d total=%d blobLen=%d",
			arnLen, matLen, ciphertextOffset, len(c),
		)
	}

	return arnLen, matLen, ciphertextOffset, nil
}

func (c CiphertextBlob) KeyArn() (string, error) {
	arnLen, _, _, err := c.validate()
	if err != nil {
		return "", err
	}

	offset := 2
	end := offset + arnLen
	arn := string(c[offset:end])

	if !strings.HasPrefix(arn, "arn:") {
		return "", fmt.Errorf("result does not appear to be an AWS KMS key")
	}

	return arn, nil
}

func (c CiphertextBlob) MaterialId() (string, error) {
	arnLen, matLen, _, err := c.validate()
	if err != nil {
		return "", err
	}

	offset := 2 + arnLen
	end := offset + matLen
	return string(c[offset:end]), nil
}

func (c CiphertextBlob) Ciphertext() ([]byte, error) {
	_, _, ciphertextOffset, err := c.validate()
	if err != nil {
		return nil, err
	}

	// Return a view (slice) into the underlying blob (no copy).
	return c[ciphertextOffset:], nil
}

//------------------------------------------------------

func (k *SymmetricKey) Encrypt(plaintext []byte, algorithm types.EncryptionAlgorithmSpec, context map[string]string) ([]byte, error) {
	if err := k.enforceKeyUsageType(types.KeyUsageTypeEncryptDecrypt); err != nil {
		return nil, err
	}

	backingKey, ok := k.BackingKeys[*k.GetMetadata().CurrentKeyMaterialId]
	if !ok {
		return nil, fmt.Errorf("backing key not found")
	}

	block, err := aes.NewCipher(backingKey.Material[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := GenerateRandomData(uint16(gcm.NonceSize()))
	additionalData := k.packContext(context)

	ciphertext := gcm.Seal(nil, nonce, plaintext, additionalData)

	nonceCiphertext := append(nonce, ciphertext...)
	result := NewCiphertextBlob(k.GetArn(), nonceCiphertext, backingKey.MaterialId())

	return result, nil
}

func (k *SymmetricKey) Decrypt(ciphertextblob []byte, algorithm types.EncryptionAlgorithmSpec, context map[string]string) ([]byte, error) {
	if err := k.enforceKeyUsageType(types.KeyUsageTypeEncryptDecrypt); err != nil {
		return nil, err
	}

	ctb := CiphertextBlob(ciphertextblob)

	materialId, err := ctb.MaterialId()
	if err != nil {
		return nil, err
	}

	ciphertext, err := ctb.Ciphertext()
	if err != nil {
		return nil, err
	}

	//---

	backingKey, ok := k.BackingKeys[materialId]
	if !ok {
		return nil, fmt.Errorf("backing key not found")
	}

	block, err := aes.NewCipher(backingKey.Material[:])
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesgcm.NonceSize()

	nonce := ciphertext[:nonceSize]

	additionalData := k.packContext(context)

	ciphertext = ciphertext[nonceSize:]

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

//func (k *SymmetricKey) Decrypt(ciphertext []byte, algorithm types.EncryptionAlgorithmSpec, context map[string]string) ([]byte, error) {
//
//}

//func (k *SymmetricKey) packCiphertextBlob(ciphertext []byte, materialId string) []byte {
//
//	/*
//		Final result will be:
//			A) The length of the ident		: 1 bytes
//			B) Length of MaterialId			: 1 bytes
//			C) The ident					: A bytes
//			D) MaterialId					: B bytes
//			E) The ciphertext				: variable/remaining bytes
//	*/
//
//	arnBytes := []byte(k.GetArn())
//	materialIdBytes := []byte(materialId)
//
//	result := make([]byte, 0, 2+len(arnBytes)+len(materialIdBytes)+len(ciphertext))
//
//	result = append(result, byte(len(arnBytes)))
//	result = append(result, byte(len(materialIdBytes)))
//	result = append(result, arnBytes...)
//	result = append(result, materialIdBytes...)
//	result = append(result, ciphertext...)
//
//	return result
//}

/*
*
We prep this Encryption Context / Additional Data as per:
https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#encrypt_context

NB: Only the order of the encryption context pairs can vary. Everything else must be identical.
*/
func (k *SymmetricKey) packContext(context map[string]string) []byte {

	if context == nil || len(context) == 0 {
		return nil
	}

	// Keys can be passed in any order, so we need to sort them to be consistent
	var keys []string
	for name := range context {
		keys = append(keys, name)
	}
	sort.Strings(keys)

	//--

	result := make([]byte, 0)

	for _, key := range keys {
		result = append(result, []byte(key)...)

		// Check there is actually a string
		if context[key] == "" {
			continue
		}

		// If there is actually a value, include it
		result = append(result, []byte(context[key])...)
	}

	return result
}
