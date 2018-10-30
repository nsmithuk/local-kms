package service

func GenerateNewKey() [32]byte {
	var key [32]byte
	copy(key[:], GenerateRandomData(32))
	return key
}
