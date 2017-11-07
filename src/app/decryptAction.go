package app

import (
	"github.com/gin-gonic/gin"
	"github.com/NSmithUK/local-kms-go/src/keys"
	"github.com/NSmithUK/local-kms-go/src/encryption"
)

func decryptAction(c *gin.Context){

	type Body struct {
		CiphertextBlob string `binding:"required"`
	}

	var body Body

	err := c.BindJSON(&body)

	if err != nil {
		// Fail if body is invalid
		return
	}

	//---

	ciphertextWithIdent, err := encryption.Base64Decode(body.CiphertextBlob)
	if err != nil {
		panic(err.Error())
	}

	keyId, ciphertext := keys.ExtractKeyIdent(ciphertextWithIdent)

	key := keys.GetKey( keyId )

	plaintext := encryption.Decrypt(key, ciphertext)

	c.IndentedJSON(200, gin.H{
		"KeyId": keyId,
		"Plaintext": plaintext,
	})
}
