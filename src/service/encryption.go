package service

import (
	"crypto/aes"
	"crypto/cipher"
	"sort"
)

func Encrypt(key [32]byte, plaintext []byte, context map[string]*string) (result []byte, err error) {

	block, err := aes.NewCipher([]byte(key[:]))
	if err != nil {
		return
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}

	nonce := GenerateRandomData(uint16(aesgcm.NonceSize()))

	additionalDate := prepareEncryptionContext(context)

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, additionalDate)

	result = append(nonce, ciphertext...)

	return
}

func Decrypt(key [32]byte, ciphertext []byte, context map[string]*string) (plaintext []byte, err error) {

	block, err := aes.NewCipher([]byte(key[:]))
	if err != nil {
		return
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}

	nonceSize := aesgcm.NonceSize()

	nonce := ciphertext[:nonceSize]

	additionalDate := prepareEncryptionContext(context)

	plaintext, err = aesgcm.Open(nil, nonce, ciphertext[nonceSize:], additionalDate)
	if err != nil {
		return
	}

	return
}

/**
	We prep this Encryption Context / Additional Data as per:
		https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#encrypt_context

		NB: Only the order of the encryption context pairs can vary. Everything else must be identical.
 */
func prepareEncryptionContext(context map[string]*string) []byte {

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

	for _, k := range keys {
		result = append(result, []byte(k)...)

		// Check there is actually a string
		if context[k] == nil {
			continue
		}

		// If there is actually a value, include it
		result = append(result, []byte(*context[k])...)
	}

	return result
}
