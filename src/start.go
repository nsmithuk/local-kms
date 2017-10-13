package main

import (
	"github.com/gin-gonic/gin"
)

func main() {

	r := gin.Default()

	r.GET("/", func(c *gin.Context) {
		c.Status(501)
	})

	r.POST("/", postHandler)

	r.Run() // listen and serve on 0.0.0.0:8080
}

func postHandler(c *gin.Context) {

	operation := c.GetHeader("X-Amz-Target")

	switch operation {
		case "TrentService.Encrypt":
			encryptAction(c)
		case "TrentService.Decrypt":
			decryptAction(c)
		default:
			c.String(501, operation + " is not implemented")
			return
	}


}

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

	key := getKey( body.KeyId )

	ciphertextBytes := encrypt(key, body.Plaintext)

	ciphertextBytesWithKeyIdent := appendKeyIdent(body.KeyId, ciphertextBytes)

	ciphertext := encode(ciphertextBytesWithKeyIdent)

	//---

	c.IndentedJSON(200, gin.H{
		"KeyId": body.KeyId,
		"CiphertextBlob": ciphertext,
	})

}

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

	ciphertextWithIdent, err := decode(body.CiphertextBlob)
	if err != nil {
		panic(err.Error())
	}

	keyId, ciphertext := extractKeyIdent(ciphertextWithIdent)

	key := getKey( keyId )

	plaintext := decrypt(key, ciphertext)

	c.IndentedJSON(200, gin.H{
		"KeyId": keyId,
		"Plaintext": plaintext,
	})
}