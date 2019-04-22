package handler

import (
	"fmt"
	"github.com/nsmithuk/local-kms/src/data"
	"github.com/nsmithuk/local-kms/src/config"
	"strings"
)

/*
	Finds a key for a given key or alias name or ARN
	And confirms that it's available to use for cryptographic operations.
 */
func (r *RequestHandler) getUsableKey(keyId string) (*data.Key, Response){

	// If it's an alias, map it to a key
	if strings.Contains(keyId, "alias/") {
		aliasArn := config.EnsureArn("", keyId)

		alias, err := r.database.LoadAlias(aliasArn)

		if err != nil {
			msg := fmt.Sprintf("Alias %s is not found.", config.ArnPrefix() + keyId)

			r.logger.Warnf(msg)
			return nil, NewNotFoundExceptionResponse(msg)
		}

		keyId = alias.TargetKeyId
	}

	//---

	// Lookup the key
	keyId = config.EnsureArn("key/", keyId)

	key, _ := r.database.LoadKey(keyId)

	if key == nil {
		msg := fmt.Sprintf("Key '%s' does not exist", keyId)
		r.logger.Warnf(msg)

		return nil, NewNotFoundExceptionResponse(msg)
	}

	//----------------------------------

	if key.Metadata.DeletionDate != 0 {
		// Key is pending deletion; cannot create alias
		msg := fmt.Sprintf("%s is pending deletion.", keyId)

		r.logger.Warnf(msg)
		return nil, NewKMSInvalidStateExceptionResponse(msg)
	}

	if !key.Metadata.Enabled {
		// Key is pending deletion; cannot create alias
		msg := fmt.Sprintf("%s is disabled.", keyId)

		r.logger.Warnf(msg)
		return nil, NewDisabledExceptionResponse(msg)
	}

	return key, Response{}
}
