// Package x509 provides pure-Go (no cgo) ASN.1 marshal/unmarshal helpers for
// ECDSA keys on these named curves:
//
//   - NIST: P-224, P-256, P-384, P-521
//   - SECG: secp256k1 (OID 1.3.132.0.10)
//
// It supports:
//
//   - PKIX SubjectPublicKeyInfo ("PUBLIC KEY"):
//     MarshalPKIXPublicKey / ParsePKIXPublicKey
//   - PKCS#8 PrivateKeyInfo ("PRIVATE KEY"):
//     MarshalPKCS8PrivateKey / ParsePKCS8PrivateKey
//
// It intentionally does NOT implement certificate parsing/verification and
// avoids any Go stdlib internal packages (e.g. internal/godebug).
//
// Note: We deliberately do NOT expose ParseECPrivateKey because SEC1 ECPrivateKey
// parsing is ambiguous if the optional curve parameters are omitted. PKCS#8
// always carries the curve OID, so it's a better, deterministic format for
// storage/parsing.
package x509ecc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// --- OIDs ---

var (
	// id-ecPublicKey: 1.2.840.10045.2.1
	oidEcPublicKey = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}

	// Named curves
	oidNamedCurveP224     = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedCurveP256     = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384     = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521     = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
	oidNamedCurveSecp256k = asn1.ObjectIdentifier{1, 3, 132, 0, 10}
)

// --- ASN.1 structures (minimal) ---

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
	Algo       algorithmIdentifier
	PrivateKey []byte // OCTET STRING containing the private key (SEC1 for EC)
	// Attributes omitted; not needed for KMS-style keys.
}

// SEC1 ECPrivateKey (RFC 5915), embedded inside PKCS#8 for EC keys.
type ecPrivateKey struct {
	Version    int
	PrivateKey []byte
	Parameters asn1.RawValue  `asn1:"optional,tag:0,explicit"`
	PublicKey  asn1.BitString `asn1:"optional,tag:1,explicit"`
}

// --- Public key: PKIX / SPKI ("PUBLIC KEY") ---

// MarshalPKIXPublicKey marshals an ECDSA public key as DER SubjectPublicKeyInfo.
// Supports P-224/P-256/P-384/P-521 and secp256k1.
func MarshalPKIXPublicKey(pub *ecdsa.PublicKey) ([]byte, error) {
	if pub == nil || pub.Curve == nil || pub.X == nil || pub.Y == nil {
		return nil, errors.New("x509: nil public key")
	}

	curveOID, ok := oidFromCurve(pub.Curve)
	if !ok {
		return nil, fmt.Errorf("x509: unsupported curve: %s", curveName(pub.Curve))
	}

	// Uncompressed EC point: 0x04 || X || Y
	point := elliptic.Marshal(pub.Curve, pub.X, pub.Y)
	if len(point) == 0 {
		return nil, errors.New("x509: failed to marshal EC point")
	}

	paramDER, _ := asn1.Marshal(curveOID)
	spki := subjectPublicKeyInfo{
		Algorithm: algorithmIdentifier{
			Algorithm: oidEcPublicKey,
			Parameters: asn1.RawValue{
				FullBytes: paramDER, // DER for OBJECT IDENTIFIER
			},
		},
		SubjectPublicKey: asn1.BitString{Bytes: point, BitLength: len(point) * 8},
	}

	return asn1.Marshal(spki)
}

// ParsePKIXPublicKey parses a DER SubjectPublicKeyInfo ("PUBLIC KEY") into an ECDSA public key.
// Supports P-224/P-256/P-384/P-521 and secp256k1.
func ParsePKIXPublicKey(der []byte) (*ecdsa.PublicKey, error) {
	var spki subjectPublicKeyInfo
	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		return nil, fmt.Errorf("x509: parse SPKI: %w", err)
	}
	if !spki.Algorithm.Algorithm.Equal(oidEcPublicKey) {
		return nil, errors.New("x509: SPKI is not id-ecPublicKey")
	}

	curveOID, err := curveOIDFromParams(spki.Algorithm.Parameters)
	if err != nil {
		return nil, err
	}
	curve := curveFromOID(curveOID)
	if curve == nil {
		return nil, fmt.Errorf("x509: unsupported curve OID: %v", curveOID)
	}

	x, y := elliptic.Unmarshal(curve, spki.SubjectPublicKey.Bytes)
	if x == nil || y == nil || !curve.IsOnCurve(x, y) {
		return nil, errors.New("x509: invalid EC public key point")
	}

	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// --- Private key: PKCS#8 ("PRIVATE KEY") ---

// MarshalPKCS8PrivateKey marshals an ECDSA private key as DER PKCS#8 PrivateKeyInfo.
// The privateKey field contains a SEC1 ECPrivateKey. We include curve parameters and public key.
func MarshalPKCS8PrivateKey(priv *ecdsa.PrivateKey) ([]byte, error) {
	if priv == nil || priv.Curve == nil || priv.D == nil {
		return nil, errors.New("x509: nil private key")
	}
	curveOID, ok := oidFromCurve(priv.Curve)
	if !ok {
		return nil, fmt.Errorf("x509: unsupported curve: %s", curveName(priv.Curve))
	}

	sec1DER, err := marshalECPrivateKeyForPKCS8(priv, curveOID)
	if err != nil {
		return nil, err
	}

	paramDER, _ := asn1.Marshal(curveOID)
	p8 := pkcs8{
		Version: 0,
		Algo: algorithmIdentifier{
			Algorithm: oidEcPublicKey,
			Parameters: asn1.RawValue{
				FullBytes: paramDER,
			},
		},
		PrivateKey: sec1DER,
	}

	return asn1.Marshal(p8)
}

// ParsePKCS8PrivateKey parses DER PKCS#8 PrivateKeyInfo ("PRIVATE KEY") into an ECDSA private key.
// Supports P-224/P-256/P-384/P-521 and secp256k1.
func ParsePKCS8PrivateKey(der []byte) (*ecdsa.PrivateKey, error) {
	var p8 pkcs8
	if _, err := asn1.Unmarshal(der, &p8); err != nil {
		return nil, fmt.Errorf("x509: parse PKCS#8: %w", err)
	}
	if p8.Version != 0 {
		return nil, errors.New("x509: unsupported PKCS#8 version")
	}
	if !p8.Algo.Algorithm.Equal(oidEcPublicKey) {
		return nil, errors.New("x509: PKCS#8 is not id-ecPublicKey")
	}

	curveOID, err := curveOIDFromParams(p8.Algo.Parameters)
	if err != nil {
		return nil, err
	}
	curve := curveFromOID(curveOID)
	if curve == nil {
		return nil, fmt.Errorf("x509: unsupported curve OID: %v", curveOID)
	}

	// Parse embedded SEC1 ECPrivateKey.
	var ec ecPrivateKey
	if _, err := asn1.Unmarshal(p8.PrivateKey, &ec); err != nil {
		return nil, fmt.Errorf("x509: parse embedded ECPrivateKey: %w", err)
	}
	if ec.Version != 1 {
		return nil, errors.New("x509: unsupported embedded ECPrivateKey version")
	}

	// If embedded parameters are present, they must match PKCS#8.
	if len(ec.Parameters.FullBytes) != 0 {
		innerOID, ierr := curveOIDFromECPrivateKeyParams(ec.Parameters)
		if ierr != nil {
			return nil, ierr
		}
		if !innerOID.Equal(curveOID) {
			return nil, errors.New("x509: curve OID mismatch between PKCS#8 and SEC1")
		}
	}

	return buildECDSAPrivateKey(curve, ec.PrivateKey)
}

// --- Helpers ---

func curveFromOID(oid asn1.ObjectIdentifier) elliptic.Curve {
	switch {
	case oid.Equal(oidNamedCurveP224):
		return elliptic.P224()
	case oid.Equal(oidNamedCurveP256):
		return elliptic.P256()
	case oid.Equal(oidNamedCurveP384):
		return elliptic.P384()
	case oid.Equal(oidNamedCurveP521):
		return elliptic.P521()
	case oid.Equal(oidNamedCurveSecp256k):
		return secp256k1.S256()
	default:
		return nil
	}
}

func oidFromCurve(c elliptic.Curve) (asn1.ObjectIdentifier, bool) {
	// Robust matching by curve Params().Name, because callers may pass
	// different instances.
	switch curveName(c) {
	case "P-224":
		return oidNamedCurveP224, true
	case "P-256":
		return oidNamedCurveP256, true
	case "P-384":
		return oidNamedCurveP384, true
	case "P-521":
		return oidNamedCurveP521, true
	case "secp256k1":
		return oidNamedCurveSecp256k, true
	default:
		return nil, false
	}
}

func curveName(c elliptic.Curve) string {
	if c == nil || c.Params() == nil {
		return ""
	}
	return c.Params().Name
}

func scalarLen(c elliptic.Curve) int {
	// Use order size, not field size.
	return (c.Params().N.BitLen() + 7) / 8
}

func curveOIDFromParams(params asn1.RawValue) (asn1.ObjectIdentifier, error) {
	if len(params.FullBytes) == 0 {
		return nil, errors.New("x509: missing EC parameters (named curve OID)")
	}
	var oid asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(params.FullBytes, &oid); err != nil {
		return nil, errors.New("x509: invalid EC parameters (expected OID)")
	}
	return oid, nil
}

func buildECDSAPrivateKey(curve elliptic.Curve, privScalar []byte) (*ecdsa.PrivateKey, error) {
	if curve == nil {
		return nil, errors.New("x509: nil curve")
	}

	d := new(big.Int).SetBytes(privScalar)
	if d.Sign() <= 0 || d.Cmp(curve.Params().N) >= 0 {
		return nil, errors.New("x509: invalid private scalar")
	}

	// Derive public key from scalar; preserve leading zeros by using fixed-length scalar bytes.
	nBytes := scalarLen(curve)
	scalar := make([]byte, nBytes)
	if len(privScalar) > nBytes {
		return nil, errors.New("x509: private scalar too large")
	}
	copy(scalar[nBytes-len(privScalar):], privScalar)

	x, y := curve.ScalarBaseMult(scalar)
	if x == nil || y == nil || !curve.IsOnCurve(x, y) {
		return nil, errors.New("x509: invalid derived public key")
	}

	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y},
		D:         d,
	}, nil
}

func marshalECPrivateKeyForPKCS8(priv *ecdsa.PrivateKey, curveOID asn1.ObjectIdentifier) ([]byte, error) {
	// Normalize scalar to fixed length.
	nBytes := scalarLen(priv.Curve)
	d := priv.D.FillBytes(make([]byte, nBytes))

	// Derive public key to ensure consistency.
	x, y := priv.Curve.ScalarBaseMult(d)
	if x == nil || y == nil || !priv.Curve.IsOnCurve(x, y) {
		return nil, errors.New("x509: invalid private scalar")
	}
	pubBytes := elliptic.Marshal(priv.Curve, x, y)

	paramDER, _ := asn1.Marshal(curveOID)
	ec := ecPrivateKey{
		Version:    1,
		PrivateKey: d,
		Parameters: asn1.RawValue{FullBytes: paramDER},
		PublicKey:  asn1.BitString{Bytes: pubBytes, BitLength: len(pubBytes) * 8},
	}
	return asn1.Marshal(ec)
}

// --- Private key: SEC1 ("EC PRIVATE KEY") ---

// ParseECPrivateKey parses a DER-encoded SEC1 ECPrivateKey ("EC PRIVATE KEY").
// Supports P-224/P-256/P-384/P-521 and secp256k1.
//
// Notes on ambiguity:
//   - If the optional curve parameters are present, parsing is deterministic.
//   - If parameters are omitted, we can only safely infer the curve if a public key
//     is present and exactly one supported curve matches it.
//   - Otherwise we return an error rather than guessing (e.g. P-256 vs secp256k1).
func ParseECPrivateKey(der []byte) (*ecdsa.PrivateKey, error) {
	var ec ecPrivateKey
	if _, err := asn1.Unmarshal(der, &ec); err != nil {
		return nil, fmt.Errorf("x509: parse ECPrivateKey: %w", err)
	}
	if ec.Version != 1 {
		return nil, errors.New("x509: unsupported ECPrivateKey version")
	}

	// If parameters are present, they're [0] EXPLICIT NamedCurve (OID).
	if len(ec.Parameters.FullBytes) != 0 {
		oid, err := curveOIDFromECPrivateKeyParams(ec.Parameters)
		if err != nil {
			return nil, err
		}
		curve := curveFromOID(oid)
		if curve == nil {
			return nil, fmt.Errorf("x509: unsupported curve OID: %v", oid)
		}
		return buildECDSAPrivateKey(curve, ec.PrivateKey)
	}

	// No parameters -> ambiguous unless we can infer uniquely from the optional public key.
	if len(ec.PublicKey.Bytes) == 0 {
		return nil, errors.New("x509: missing EC parameters (named curve OID)")
	}

	// Try each supported curve; accept exactly one match.
	candidates := []elliptic.Curve{
		elliptic.P224(),
		elliptic.P256(),
		elliptic.P384(),
		elliptic.P521(),
		secp256k1.S256(),
	}

	var match *ecdsa.PrivateKey
	for _, c := range candidates {
		// Build from scalar; validates 0 < d < N and derives pub.
		priv, err := buildECDSAPrivateKey(c, ec.PrivateKey)
		if err != nil {
			continue
		}

		// Compare derived public key to the embedded public key.
		// (Embedded is expected to be uncompressed point 0x04||X||Y.)
		want := ec.PublicKey.Bytes
		got := elliptic.Marshal(priv.Curve, priv.PublicKey.X, priv.PublicKey.Y)
		if len(got) == 0 {
			continue
		}
		if !bytesEqual(got, want) {
			continue
		}

		if match != nil {
			// More than one curve matched the embedded public key.
			return nil, errors.New("x509: ambiguous EC private key: curve parameters omitted")
		}
		match = priv
	}

	if match == nil {
		return nil, errors.New("x509: invalid EC private key")
	}
	return match, nil
}

// curveOIDFromECPrivateKeyParams extracts the named-curve OID from the SEC1
// ECPrivateKey parameters field, which is [0] EXPLICIT OBJECT IDENTIFIER.
//
// Your existing curveOIDFromParams expects raw OBJECT IDENTIFIER DER.
// SEC1 wraps it in an explicit context-specific tag, so we unwrap that here.
func curveOIDFromECPrivateKeyParams(params asn1.RawValue) (asn1.ObjectIdentifier, error) {
	if len(params.FullBytes) == 0 {
		return nil, errors.New("x509: missing EC parameters (named curve OID)")
	}

	// First try direct (in case FullBytes already contains the OID DER).
	var oid asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(params.FullBytes, &oid); err == nil {
		return oid, nil
	}

	// Otherwise unwrap the EXPLICIT tag: decode the outer RawValue,
	// then decode its contents as an OID.
	var outer asn1.RawValue
	if _, err := asn1.Unmarshal(params.FullBytes, &outer); err != nil {
		return nil, errors.New("x509: invalid EC parameters (expected OID)")
	}
	if len(outer.Bytes) == 0 {
		return nil, errors.New("x509: invalid EC parameters (empty)")
	}
	if _, err := asn1.Unmarshal(outer.Bytes, &oid); err != nil {
		return nil, errors.New("x509: invalid EC parameters (expected OID)")
	}
	return oid, nil
}

// bytesEqual is a small helper to avoid pulling in subtle/constant-time concerns here.
// (Public key bytes are not secret.)
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
