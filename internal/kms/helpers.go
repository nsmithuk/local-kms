package kms

import "encoding/base64"

func EncodeMarker(in string) *string {
	nextMarkerB64 := base64.StdEncoding.EncodeToString([]byte(in))
	return &nextMarkerB64
}

func DecodeMarker(in *string) (*string, error) {
	data, err := base64.StdEncoding.DecodeString(*in)
	if err != nil {
		return nil, err
	}
	nextMarketStr := string(data)
	return &nextMarketStr, nil
}
