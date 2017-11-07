package app

import (
	"github.com/gin-gonic/gin"
	"github.com/NSmithUK/local-kms-go/src/keys"
	"github.com/NSmithUK/local-kms-go/src/encryption"
)

func encryptAction(c *gin.Context){

	type Body struct {
		KeyId string `binding:"required"`
		Plaintext string `binding:"required"`
	}

	var body Body

	err := c.BindJSON(&body)

	if err != nil {
		// Fail if body is invalid
		return
	}

	//---

	if len(body.Plaintext) > 4096 {
		c.String(400, "Plaintext too long")
		return
	}

	//---

	key := keys.GetKey( body.KeyId )

	ciphertextBytes := encryption.Encrypt(key, body.Plaintext)

	ciphertextBytesWithKeyIdent := keys.AppendKeyIdent(body.KeyId, ciphertextBytes)

	ciphertext := encryption.Base64Encode(ciphertextBytesWithKeyIdent)

	//---

	c.IndentedJSON(200, gin.H{
		"KeyId": body.KeyId,
		"CiphertextBlob": ciphertext,
	})

}
