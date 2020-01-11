package cmk

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"github.com/nsmithuk/local-kms/src/service"
	"sort"
)

func (k *AesKey) Decrypt(version uint32, ciphertext []byte, context map[string]*string) (plaintext []byte, err error) {

	if version >= uint32(len(k.BackingKeys)) {
		err = errors.New("required version of backing key is invalid")
		return
	}

	key := k.BackingKeys[version]

	//---

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

	additionalDate := prepareAesEncryptionContext(context)

	plaintext, err = aesgcm.Open(nil, nonce, ciphertext[nonceSize:], additionalDate)
	if err != nil {
		return
	}

	return
}

//--------------------------------------------------------------------

func (k *AesKey) EncryptAndPackage(plaintext []byte, context map[string]*string) (result []byte, err error) {

	keyVersion := len(k.BackingKeys) - 1
	dataKey := k.BackingKeys[keyVersion]

	//----------------------------
	// Encrypt

	ciphertext, err := k.encrypt(dataKey, plaintext, context)
	if err != nil {
		return
	}

	//----------------------------
	// Package

	/*
		Final result will be:
			A) The length of the ident		: 1 bytes
			B) The ident					: A bytes
			C) The Data Key version			: 4 bytes
			D) The ciphertext				: variable/remaining bytes
	*/

	identBytes := []byte(k.GetArn())

	v := make([]byte, 4)
	binary.LittleEndian.PutUint32(v, uint32(keyVersion))

	result = []byte{byte(len(identBytes))}
	result = append( result, identBytes... )
	result = append( result, v... )
	result = append( result, ciphertext... )

	return
}

func (k *AesKey) encrypt(key [32]byte, plaintext []byte, context map[string]*string) (result []byte, err error) {

	block, err := aes.NewCipher([]byte(key[:]))
	if err != nil {
		return
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}

	nonce := service.GenerateRandomData(uint16(aesgcm.NonceSize()))

	additionalDate := prepareAesEncryptionContext(context)

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, additionalDate)

	result = append(nonce, ciphertext...)

	return
}

/**
We prep this Encryption Context / Additional Data as per:
	https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#encrypt_context

	NB: Only the order of the encryption context pairs can vary. Everything else must be identical.
*/
func prepareAesEncryptionContext(context map[string]*string) []byte {

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
