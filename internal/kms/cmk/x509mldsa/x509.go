package x509mldsa

import (
	"bytes"
	"crypto"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/nsmithuk/ml-dsa/mldsa44"
	"github.com/nsmithuk/ml-dsa/mldsa65"
	"github.com/nsmithuk/ml-dsa/mldsa87"
)

var (
	oidMLDSA44 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	oidMLDSA65 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	oidMLDSA87 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}
)

var (
	ErrUnsupportedAlgorithm = errors.New("x509mldsa: unsupported algorithm")
	ErrInvalidKey           = errors.New("x509mldsa: invalid key encoding")
	ErrWrongPEMType         = errors.New("x509mldsa: unexpected PEM block type")
)

const mldsaSeedSize = 32

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type subjectPublicKeyInfo struct {
	Algorithm        algorithmIdentifier
	SubjectPublicKey asn1.BitString
}

type pkcs8 struct {
	Version    int
	Algorithm  algorithmIdentifier
	PrivateKey []byte // OCTET STRING contents
}

type mldsaPrivateKeyBoth struct {
	Seed        []byte
	ExpandedKey []byte
}

// ---- Public key marshal/parse ----

func MarshalPKIXPublicKey(pub any) ([]byte, error) {
	switch pk := pub.(type) {
	case *mldsa44.PublicKey:
		raw := pk.Bytes()
		if len(raw) == 0 {
			return nil, ErrInvalidKey
		}
		return marshalSPKI(oidMLDSA44, raw)

	case *mldsa65.PublicKey:
		raw := pk.Bytes()
		if len(raw) == 0 {
			return nil, ErrInvalidKey
		}
		return marshalSPKI(oidMLDSA65, raw)

	case *mldsa87.PublicKey:
		raw := pk.Bytes()
		if len(raw) == 0 {
			return nil, ErrInvalidKey
		}
		return marshalSPKI(oidMLDSA87, raw)

	default:
		return nil, fmt.Errorf("%w: %T", ErrUnsupportedAlgorithm, pub)
	}
}

func marshalSPKI(oid asn1.ObjectIdentifier, rawPub []byte) ([]byte, error) {
	if len(rawPub) == 0 {
		return nil, ErrInvalidKey
	}
	spki := subjectPublicKeyInfo{
		Algorithm: algorithmIdentifier{
			Algorithm: oid,
			// RFC 9881: parameters absent (NULL tolerated on parse)
		},
		SubjectPublicKey: asn1.BitString{
			Bytes:     rawPub,
			BitLength: len(rawPub) * 8,
		},
	}
	return asn1.Marshal(spki)
}

func ParsePKIXPublicKey(der []byte) (crypto.PublicKey, error) {
	var spki subjectPublicKeyInfo
	rest, err := asn1.Unmarshal(der, &spki)
	if err != nil || len(rest) != 0 {
		return nil, ErrInvalidKey
	}
	if spki.SubjectPublicKey.BitLength%8 != 0 {
		return nil, ErrInvalidKey
	}
	raw := spki.SubjectPublicKey.Bytes

	// Accept absent parameters; also tolerate explicit NULL.
	if spki.Algorithm.Parameters.FullBytes != nil {
		if !(spki.Algorithm.Parameters.Class == asn1.ClassUniversal &&
			spki.Algorithm.Parameters.Tag == asn1.TagNull) {
			return nil, ErrInvalidKey
		}
	}

	switch {
	case spki.Algorithm.Algorithm.Equal(oidMLDSA44):
		pk, err := mldsa44.PublicKeyFromBytes(raw)
		if err != nil {
			return nil, ErrInvalidKey
		}
		return pk, nil

	case spki.Algorithm.Algorithm.Equal(oidMLDSA65):
		pk, err := mldsa65.PublicKeyFromBytes(raw)
		if err != nil {
			return nil, ErrInvalidKey
		}
		return pk, nil

	case spki.Algorithm.Algorithm.Equal(oidMLDSA87):
		pk, err := mldsa87.PublicKeyFromBytes(raw)
		if err != nil {
			return nil, ErrInvalidKey
		}
		return pk, nil

	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, spki.Algorithm.Algorithm.String())
	}
}

// ---- Private key parse (PKCS#8) ----

func ParsePKCS8PrivateKey(der []byte) (crypto.PrivateKey, error) {
	var p8 pkcs8
	rest, err := asn1.Unmarshal(der, &p8)
	if err != nil || len(rest) != 0 {
		return nil, ErrInvalidKey
	}
	if p8.Version != 0 {
		return nil, ErrInvalidKey
	}

	seed, expanded, err := parseMLDSAPrivateKeyChoice(p8.PrivateKey)
	if err != nil {
		return nil, err
	}

	switch {
	case p8.Algorithm.Algorithm.Equal(oidMLDSA44):
		return buildPrivateKey44(seed, expanded)
	case p8.Algorithm.Algorithm.Equal(oidMLDSA65):
		return buildPrivateKey65(seed, expanded)
	case p8.Algorithm.Algorithm.Equal(oidMLDSA87):
		return buildPrivateKey87(seed, expanded)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, p8.Algorithm.Algorithm.String())
	}
}

func parseMLDSAPrivateKeyChoice(derChoice []byte) (seed []byte, expanded []byte, err error) {
	var rv asn1.RawValue
	rest, e := asn1.Unmarshal(derChoice, &rv)
	if e != nil || len(rest) != 0 {
		return nil, nil, ErrInvalidKey
	}

	switch {
	case rv.Class == asn1.ClassContextSpecific && rv.Tag == 0:
		if len(rv.Bytes) == 0 {
			return nil, nil, ErrInvalidKey
		}
		return rv.Bytes, nil, nil

	case rv.Class == asn1.ClassUniversal && rv.Tag == asn1.TagOctetString:
		if len(rv.Bytes) == 0 {
			return nil, nil, ErrInvalidKey
		}
		return nil, rv.Bytes, nil

	case rv.Class == asn1.ClassUniversal && rv.Tag == asn1.TagSequence:
		var both mldsaPrivateKeyBoth
		rest2, e2 := asn1.Unmarshal(rv.FullBytes, &both)
		if e2 != nil || len(rest2) != 0 {
			return nil, nil, ErrInvalidKey
		}
		if len(both.Seed) == 0 || len(both.ExpandedKey) == 0 {
			return nil, nil, ErrInvalidKey
		}
		return both.Seed, both.ExpandedKey, nil

	default:
		return nil, nil, ErrInvalidKey
	}
}

func buildPrivateKey44(seed, expanded []byte) (crypto.PrivateKey, error) {
	switch {
	case len(expanded) > 0:
		sk, err := mldsa44.PrivateKeyFromExpanded(expanded)
		if err != nil {
			return nil, ErrInvalidKey
		}
		if len(seed) > 0 {
			if err := checkSeedMatchesExpanded44(seed, sk.(*mldsa44.PrivateKey)); err != nil {
				return nil, err
			}
		}
		return sk, nil

	case len(seed) == mldsaSeedSize:
		sk, err := mldsa44.PrivateKeyFromSeed(seed)
		if err != nil {
			return nil, ErrInvalidKey
		}
		return sk, nil

	default:
		return nil, ErrInvalidKey
	}
}

func buildPrivateKey65(seed, expanded []byte) (crypto.PrivateKey, error) {
	switch {
	case len(expanded) > 0:
		sk, err := mldsa65.PrivateKeyFromExpanded(expanded)
		if err != nil {
			return nil, ErrInvalidKey
		}
		if len(seed) > 0 {
			if err := checkSeedMatchesExpanded65(seed, sk.(*mldsa65.PrivateKey)); err != nil {
				return nil, err
			}
		}
		return sk, nil

	case len(seed) == mldsaSeedSize:
		sk, err := mldsa65.PrivateKeyFromSeed(seed)
		if err != nil {
			return nil, ErrInvalidKey
		}
		return sk, nil

	default:
		return nil, ErrInvalidKey
	}
}

func buildPrivateKey87(seed, expanded []byte) (crypto.PrivateKey, error) {
	switch {
	case len(expanded) > 0:
		sk, err := mldsa87.PrivateKeyFromExpanded(expanded)
		if err != nil {
			return nil, ErrInvalidKey
		}
		if len(seed) > 0 {
			if err := checkSeedMatchesExpanded87(seed, sk.(*mldsa87.PrivateKey)); err != nil {
				return nil, err
			}
		}
		return sk, nil

	case len(seed) == mldsaSeedSize:
		sk, err := mldsa87.PrivateKeyFromSeed(seed)
		if err != nil {
			return nil, ErrInvalidKey
		}
		return sk, nil

	default:
		return nil, ErrInvalidKey
	}
}

func checkSeedMatchesExpanded44(seed []byte, sk *mldsa44.PrivateKey) error {
	if len(seed) != mldsaSeedSize {
		return ErrInvalidKey
	}
	skFromSeed, err := mldsa44.PrivateKeyFromSeed(seed)
	if err != nil {
		return ErrInvalidKey
	}
	pk1 := skFromSeed.PublicKey()
	pk2 := sk.PublicKey()
	if !bytes.Equal(pk1.Bytes(), pk2.Bytes()) {
		return ErrInvalidKey
	}
	return nil
}

func checkSeedMatchesExpanded65(seed []byte, sk *mldsa65.PrivateKey) error {
	if len(seed) != mldsaSeedSize {
		return ErrInvalidKey
	}
	skFromSeed, err := mldsa65.PrivateKeyFromSeed(seed)
	if err != nil {
		return ErrInvalidKey
	}
	pk1 := skFromSeed.PublicKey()
	pk2 := sk.PublicKey()
	if !bytes.Equal(pk1.Bytes(), pk2.Bytes()) {
		return ErrInvalidKey
	}
	return nil
}

func checkSeedMatchesExpanded87(seed []byte, sk *mldsa87.PrivateKey) error {
	if len(seed) != mldsaSeedSize {
		return ErrInvalidKey
	}
	skFromSeed, err := mldsa87.PrivateKeyFromSeed(seed)
	if err != nil {
		return ErrInvalidKey
	}
	pk1 := skFromSeed.PublicKey()
	pk2 := sk.PublicKey()
	if !bytes.Equal(pk1.Bytes(), pk2.Bytes()) {
		return ErrInvalidKey
	}
	return nil
}

// ---- PEM helpers ----

func ParsePEMPrivateKey(pemBytes []byte) (crypto.PrivateKey, error) {
	for {
		var block *pem.Block
		block, pemBytes = pem.Decode(pemBytes)
		if block == nil {
			return nil, ErrInvalidKey
		}
		if block.Type != "PRIVATE KEY" {
			continue
		}
		return ParsePKCS8PrivateKey(block.Bytes)
	}
}

func ParsePEMPublicKey(pemBytes []byte) (crypto.PublicKey, error) {
	for {
		var block *pem.Block
		block, pemBytes = pem.Decode(pemBytes)
		if block == nil {
			return nil, ErrInvalidKey
		}
		if block.Type != "PUBLIC KEY" {
			continue
		}
		return ParsePKIXPublicKey(block.Bytes)
	}
}
