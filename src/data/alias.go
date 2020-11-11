package data

type Alias struct {
	AliasArn    string `yaml:"AliasArn"`
	AliasName   string `yaml:"AliasName"`
	TargetKeyId string `yaml:"TargetKeyId"`
}
