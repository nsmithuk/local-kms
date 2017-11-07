package app

import (
	"github.com/gin-gonic/gin"
)

func Run() {

	router := gin.Default()

	router.GET("/", func(c *gin.Context) {
		c.Status(501)
	})

	router.POST("/", postHandler)

	//---

	router.Run()

}
