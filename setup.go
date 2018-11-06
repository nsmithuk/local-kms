package main

import (
	"log"
	"gopkg.in/yaml.v2"
	"github.com/nsmithuk/local-kms/src/data"
	"github.com/davecgh/go-spew/spew"
	"github.com/nsmithuk/local-kms/src/config"
	"time"
)

var input = `
Keys:
  - Metadata:
      KeyId: bc436485-5092-42b8-92a3-0aa8b93536dc
      Description: "Key description"
    NextKeyRotation: "2019-02-12T15:19:21+00:00"
    BackingKeys:
      - 34743777217A25432A46294A404E635266556A586E3272357538782F413F4428
      - 614E645267556B58703273357638792F423F4528472B4B6250655368566D5971

Aliases:
  - AliasName: alias/testing
    TargetKeyId: bc436485-5092-42b8-92a3-0aa8b93536dc

`

func main() {

	type Input struct {
		Keys	[]data.Key		`yaml:"Keys"`
		Aliases	[]data.Alias	`yaml:"Aliases"`
	}

	t := Input{}

	err := yaml.Unmarshal([]byte(input), &t)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	//-----------------------------------------
	// Apply defaults

	for i, key := range t.Keys {
		t.Keys[i].Metadata.Arn			= config.ArnPrefix() + "key/" + key.Metadata.KeyId
		t.Keys[i].Metadata.AWSAccountId = config.AWSAccountId
		t.Keys[i].Metadata.CreationDate = time.Now().Unix()
		t.Keys[i].Metadata.Enabled		= true
		t.Keys[i].Metadata.KeyManager	= "CUSTOMER"
		t.Keys[i].Metadata.KeyState		= "Enabled"
		t.Keys[i].Metadata.KeyUsage		= "ENCRYPT_DECRYPT"
		t.Keys[i].Metadata.Origin		= "AWS_KMS"
	}

	for i, alias := range t.Aliases {
		t.Aliases[i].AliasArn = config.ArnPrefix() + alias.AliasName
	}

	//-----------------------------------------

	spew.Dump(t)
}
