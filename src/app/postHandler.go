package app

import "github.com/gin-gonic/gin"

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
