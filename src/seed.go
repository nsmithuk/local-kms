package src

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/nsmithuk/local-kms/src/cmk"
	"github.com/nsmithuk/local-kms/src/config"
	"github.com/nsmithuk/local-kms/src/data"
	"github.com/syndtr/goleveldb/leveldb"
	"gopkg.in/yaml.v2"
)

func seed(path string, database *data.Database) {

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

	type InputSymmetric struct {
		Aes []cmk.AesKey `yaml:"Aes"`
	}

	type InputKeys struct {
		Symmetric InputSymmetric `yaml:"Symmetric"`
	}

	type Input struct {
		Keys    InputKeys    `yaml:"Keys"`
		Aliases []data.Alias `yaml:"Aliases"`
	}

	seed := Input{}

	var aesKeys []cmk.AesKey
	var aliases []data.Alias

	err = yaml.Unmarshal([]byte(context), &seed)
	if err != nil {

		logger.Warningln(fmt.Sprintf("Error parsing YAML at path %s: %s; attempting to parse legacy format.", path, err))

		//------------------------------------------------------
		// Try processing the document in the legacy format

		// TODO Support for the legacy format will be removed in future versions.

		type InputOld struct {
			Keys    []cmk.AesKey `yaml:"Keys"`
			Aliases []data.Alias `yaml:"Aliases"`
		}

		seed := InputOld{}
		err = yaml.Unmarshal([]byte(context), &seed)
		if err != nil {
			logger.Errorln(fmt.Sprintf("Error parsing YAML at path %s: %s; skipping.", path, err))
			return
		}

		if len(seed.Keys) > 0 {
			logger.Warnf("The seed file is using a legacy format. Please update to the latest version. " +
				"Support for the legacy version will be removed in future versions.\n")
		}

		for _, key := range seed.Keys {
			aesKeys = append(aesKeys, key)
		}

		for _, alias := range seed.Aliases {
			aliases = append(aliases, alias)
		}

		//------------------------------------------------------

	} else {
		for _, key := range seed.Keys.Symmetric.Aes {
			aesKeys = append(aesKeys, key)
		}
		for _, alias := range seed.Aliases {
			aliases = append(aliases, alias)
		}
	}

	logger.Infof("Importing data from seed file %s\n", path)

	//-----------------------------------------
	// Apply defaults

	for i, key := range aesKeys {
		aesKeys[i].Metadata.Arn = config.ArnPrefix() + "key/" + key.Metadata.KeyId
		aesKeys[i].Metadata.AWSAccountId = config.AWSAccountId
		aesKeys[i].Metadata.CreationDate = time.Now().Unix()
		aesKeys[i].Metadata.Enabled = true
		aesKeys[i].Metadata.KeyManager = "CUSTOMER"
		aesKeys[i].Metadata.KeyState = cmk.KeyStateEnabled
		aesKeys[i].Metadata.KeyUsage = cmk.UsageEncryptDecrypt
		aesKeys[i].Metadata.Origin = key.Metadata.Origin

		if key.Metadata.Origin == cmk.KeyOriginExternal && len(key.BackingKeys) == 0 {
			aesKeys[i].Metadata.KeyState = cmk.KeyStatePendingImport
			aesKeys[i].Metadata.Enabled = false
		}

		aesKeys[i].Metadata.CustomerMasterKeySpec = cmk.SpecSymmetricDefault
		aesKeys[i].Metadata.EncryptionAlgorithms = []cmk.EncryptionAlgorithm{cmk.EncryptionAlgorithmAes}

		aesKeys[i].Type = cmk.TypeAes
	}

	for i, alias := range aliases {
		aliases[i].AliasArn = config.ArnPrefix() + alias.AliasName
	}

	//-----------------------------------------
	// Save to database

	keysAdded := 0
	for _, key := range aesKeys {

		if _, err := database.LoadKey(key.Metadata.Arn); err != leveldb.ErrNotFound {
			logger.Warnf("Key %s already exists; skipping key", key.Metadata.KeyId)
			continue
		}

		database.SaveKey(&key)
		keysAdded++
	}

	aliasesAdded := 0
	for _, alias := range aliases {

		if _, err := database.LoadAlias(alias.AliasArn); err != leveldb.ErrNotFound {
			logger.Warnf("Alias %s already exists; skipping alias\n", alias.AliasName)
			continue
		}

		database.SaveAlias(&alias)
		aliasesAdded++
	}

	logger.Infof("%d new keys and %d new aliases added\n", keysAdded, aliasesAdded)
}
