package main

import (
	"os"
	"github.com/nsmithuk/local-kms/src"
)

func main() {

	port := os.Getenv("PORT")

	if port == "" {
		port = "9090"
	}

	src.Run(port)
}
