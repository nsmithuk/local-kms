package src

import (
	"fmt"
	"github.com/nsmithuk/local-kms/src/cmk"
	"github.com/nsmithuk/local-kms/src/config"
	"github.com/nsmithuk/local-kms/src/data"
	"github.com/syndtr/goleveldb/leveldb"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"
)

func seed(path string, database *data.Database){

	if path == "" {
		logger.Infoln("No seed path passed; skipping.")
		return
	}

	path, _ = filepath.Abs(path)

	if _, err := os.Stat(path); os.IsNotExist(err) {
		logger.Infoln(fmt.Sprintf("No file found at path %s; skipping seeding.", path))
		return
	}

	context, err := ioutil.ReadFile(path)
	if err != nil {
		logger.Errorln(fmt.Sprintf("Unable to read seed content of file at path %s; skipping.", path))
		return
	}

	//---

	type Input struct {
		Keys	[]cmk.AesKey	`yaml:"Keys"`
		Aliases	[]data.Alias	`yaml:"Aliases"`
	}

	seed := Input{}

	err = yaml.Unmarshal([]byte(context), &seed)
	if err != nil {
		logger.Errorln(fmt.Sprintf("Error parsing YAML at path %s: %s; skipping.", path, err))
	}

	logger.Infof("Importing data from seed file %s\n", path)

	//-----------------------------------------
	// Apply defaults

	for i, key := range seed.Keys {
		seed.Keys[i].Metadata.Arn			= config.ArnPrefix() + "key/" + key.Metadata.KeyId
		seed.Keys[i].Metadata.AWSAccountId = config.AWSAccountId
		seed.Keys[i].Metadata.CreationDate = time.Now().Unix()
		seed.Keys[i].Metadata.Enabled		= true
		seed.Keys[i].Metadata.KeyManager	= "CUSTOMER"
		seed.Keys[i].Metadata.KeyState		= "Enabled"
		seed.Keys[i].Metadata.KeyUsage		= cmk.UsageEncryptDecrypt
		seed.Keys[i].Metadata.Origin		= "AWS_KMS"

		seed.Keys[i].Metadata.CustomerMasterKeySpec		= cmk.SpecSymmetricDefault
		seed.Keys[i].Metadata.EncryptionAlgorithms		= []cmk.EncryptionAlgorithm{cmk.EncryptionAlgorithmAes}

		seed.Keys[i].Type					= cmk.TypeAes
	}

	for i, alias := range seed.Aliases {
		seed.Aliases[i].AliasArn = config.ArnPrefix() + alias.AliasName
	}

	//-----------------------------------------
	// Save to database

	keysAdded := 0
	for _, key := range seed.Keys {

		if _, err := database.LoadKey(key.Metadata.Arn); err != leveldb.ErrNotFound {
			logger.Warnf("Key %s already exists; skipping key", key.Metadata.KeyId)
			continue
		}

		database.SaveKey(&key)
		keysAdded++
	}

	aliasesAdded := 0
	for _, alias := range seed.Aliases {

		if _, err := database.LoadAlias(alias.AliasArn); err != leveldb.ErrNotFound {
			logger.Warnf("Alias %s already exists; skipping alias\n", alias.AliasName)
			continue
		}

		database.SaveAlias(&alias)
		aliasesAdded++
	}

	logger.Infof("%d new keys and %d new aliases added\n", keysAdded, aliasesAdded)
}
