// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
)

// pkcs8 reflects an ASN.1, PKCS #8 PrivateKey. See
// ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-8/pkcs-8v1_2.asn
// and RFC 5208.
type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
	// optional attributes omitted.
}

// MarshalPKCS8PrivateKey converts a private key to PKCS #8, ASN.1 DER form.
//
// The following key types are currently supported: *rsa.PrivateKey, *ecdsa.PrivateKey
// and ed25519.PrivateKey. Unsupported key types result in an error.
//
// This kind of key is commonly encoded in PEM blocks of type "PRIVATE KEY".
func MarshalPKCS8PrivateKey(key interface{}) ([]byte, error) {
	var privKey pkcs8

	switch k := key.(type) {
	case *rsa.PrivateKey:
		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm:  oidPublicKeyRSA,
			Parameters: asn1.NullRawValue,
		}
		privKey.PrivateKey = MarshalPKCS1PrivateKey(k)

	case *ecdsa.PrivateKey:
		oid, ok := oidFromNamedCurve(k.Curve)
		if !ok {
			return nil, errors.New("x509: unknown curve while marshaling to PKCS#8")
		}

		oidBytes, err := asn1.Marshal(oid)
		if err != nil {
			return nil, errors.New("x509: failed to marshal curve OID: " + err.Error())
		}

		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm: oidPublicKeyECDSA,
			Parameters: asn1.RawValue{
				FullBytes: oidBytes,
			},
		}

		if privKey.PrivateKey, err = marshalECPrivateKeyWithOID(k, nil); err != nil {
			return nil, errors.New("x509: failed to marshal EC private key while building PKCS#8: " + err.Error())
		}

	case ed25519.PrivateKey:
		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm: oidPublicKeyEd25519,
		}
		curvePrivateKey, err := asn1.Marshal(k.Seed())
		if err != nil {
			return nil, fmt.Errorf("x509: failed to marshal private key: %v", err)
		}
		privKey.PrivateKey = curvePrivateKey

	default:
		return nil, fmt.Errorf("x509: unknown key type while marshaling PKCS#8: %T", key)
	}

	return asn1.Marshal(privKey)
}
