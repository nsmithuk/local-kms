package handler

func (r *RequestHandler) GenerateDataKeyPairWithoutPlaintext() Response {
	errResponse, keyResponse := r.generateDataKeyPair()

	if !errResponse.Empty() {
		return errResponse
	}

	// Strip out the Plaintext
	keyResponse.PrivateKeyPlaintext = []byte{}

	//---

	r.logger.Infof("Data key pair generated without plaintext: %s\n", keyResponse.KeyId)

	return NewResponse(200, keyResponse)
}
