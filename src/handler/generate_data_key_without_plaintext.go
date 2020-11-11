package handler

func (r *RequestHandler) GenerateDataKeyWithoutPlaintext() Response {
	errResponse, keyResponse := r.generateDataKey()

	if !errResponse.Empty() {
		return errResponse
	}

	// Strip out the Plaintext
	keyResponse.Plaintext = []byte{}

	//---

	r.logger.Infof("Data key generated without plaintext: %s\n", keyResponse.KeyId)

	return NewResponse(200, keyResponse)
}
