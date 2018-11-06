package src

import (
	"os"
	"fmt"
	"io/ioutil"
	"gopkg.in/yaml.v2"
	"github.com/nsmithuk/local-kms/src/data"
	"github.com/nsmithuk/local-kms/src/config"
	"time"
)

func Seed(path string){

	if path == "" {
		logger.Infoln("No seed path passed; skipping.")
		return
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		logger.Errorln(fmt.Sprintf("No file found at path %s; skipping.", path))
		return
	}

	context, err := ioutil.ReadFile(path)
	if err != nil {
		logger.Errorln(fmt.Sprintf("Unable to read content of file at path %s; skipping.", path))
		return
	}

	//---

	type Input struct {
		Keys	[]data.Key		`yaml:"Keys"`
		Aliases	[]data.Alias	`yaml:"Aliases"`
	}

	seed := Input{}

	err = yaml.Unmarshal([]byte(context), &seed)
	if err != nil {
		logger.Errorln(fmt.Sprintf("Error parsing YAML at path %s: %s; skipping.", path, err))
	}

	//-----------------------------------------
	// Apply defaults

	for i, key := range seed.Keys {
		seed.Keys[i].Metadata.Arn			= config.ArnPrefix() + "key/" + key.Metadata.KeyId
		seed.Keys[i].Metadata.AWSAccountId = config.AWSAccountId
		seed.Keys[i].Metadata.CreationDate = time.Now().Unix()
		seed.Keys[i].Metadata.Enabled		= true
		seed.Keys[i].Metadata.KeyManager	= "CUSTOMER"
		seed.Keys[i].Metadata.KeyState		= "Enabled"
		seed.Keys[i].Metadata.KeyUsage		= "ENCRYPT_DECRYPT"
		seed.Keys[i].Metadata.Origin		= "AWS_KMS"
	}

	for i, alias := range seed.Aliases {
		seed.Aliases[i].AliasArn = config.ArnPrefix() + alias.AliasName
	}

	//-----------------------------------------
	// Save to database

	database := getDatabase()
	defer database.Close()

	//---

	for _, key := range seed.Keys {
		database.SaveKey(&key)
	}

	for _, alias := range seed.Aliases {
		database.SaveAlias(&alias)
	}

	logger.Infof("%d keys and %d aliases added from seed file", len(seed.Keys), len(seed.Aliases))
}
