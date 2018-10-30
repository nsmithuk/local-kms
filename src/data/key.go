package data

type Key struct {
	Metadata 	KeyMetadata
	BackingKeys	[][32]byte
}

type KeyMetadata struct {
	AWSAccountId string `json:",omitempty"`
	Arn string `json:",omitempty"`
	CreationDate int64 `json:",omitempty"`
	DeletionDate int64 `json:",omitempty"`
	Description *string	`json:",omitempty"`
	Enabled bool `json:",omitempty"`
	ExpirationModel string `json:",omitempty"`
	KeyId string `json:",omitempty"`
	KeyManager string `json:",omitempty"`
	KeyState string `json:",omitempty"`
	KeyUsage string `json:",omitempty"`
	Origin string `json:",omitempty"`
	ValidTo int64 `json:",omitempty"`
}

//-------------------------
// Mapped Types

/*
//type KeyMetadata kms.KeyMetadata

func (t KeyMetadata) MarshalJSON() ([]byte, error) {
	type Alias KeyMetadata

	var ValidTo *int64
	var CreationDate *int64
	var DeletionDate *int64

	if t.ValidTo != nil {
		val := t.ValidTo.UnixNano()
		ValidTo = &val
	}

	if t.CreationDate != nil {
		val := t.CreationDate.UnixNano()
		CreationDate = &val
	}

	if t.DeletionDate != nil {
		val := t.DeletionDate.UnixNano()
		DeletionDate = &val
	}

	return json.Marshal(&struct {
		ValidTo			*int64
		CreationDate	*int64
		DeletionDate	*int64
		Alias
	}{
		ValidTo: 		ValidTo,
		CreationDate: 	CreationDate,
		DeletionDate: 	DeletionDate,
		Alias:    		(Alias)(t),
	})
}
*/
