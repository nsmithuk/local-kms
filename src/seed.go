package src

import (
	"os"
	"fmt"
	"io/ioutil"
	"gopkg.in/yaml.v2"
	"github.com/nsmithuk/local-kms/src/data"
)

func seed(path string){

	if path == "" {
		logger.Debugln("No seed path passed; skipping.")
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
		logger.Errorln("Error parsing YAML in seeding file; skipping.")
		logger.Errorln(fmt.Sprintf("Error parsing YAML at path %s: %s; skipping.", path, err))
	}


	logger.Infoln("here")

}
