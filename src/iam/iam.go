package iam

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"gopkg.in/yaml.v2"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// AWS Signature Version '4' constants.
const (
	signV4Algorithm      = "AWS4-HMAC-SHA256"
	yyyymmdd             = "20060102"
	iso8601Format        = "20060102T150405Z"
	accountAnonymousName = "anonymous"
	accountAdminName     = "admin"
	emptySHA256          = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// Authorization type.
type authType int

const (
	authTypeUnknown authType = iota
	authTypeAnonymous
	authTypeSigned
)

// Verify if request has AWS Signature Version '4'.
func isRequestSignatureV4(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get("Authorization"), signV4Algorithm)
}

func getRequestAuthType(r *http.Request) authType {
	if isRequestSignatureV4(r) {
		return authTypeSigned
	} else if _, ok := r.Header["Authorization"]; !ok {
		return authTypeAnonymous
	}
	return authTypeUnknown
}

type IdentityAccessManagement struct {
	identities    []*Identity
	isAuthEnabled bool
	domain        string
}

type Identity struct {
	Name        string
	AccountId   string
	Credentials []*Credential
	Targets     []string
}

func (i *Identity) isAnonymous() bool {
	return i.Name == accountAnonymousName
}

func (identity *Identity) isAdmin() bool {
	for _, a := range identity.Targets {
		if a == accountAdminName {
			return true
		}
	}
	return false
}

type Credential struct {
	AccessKey string
	SecretKey string
}

func (iam *IdentityAccessManagement) IsEnabled() bool {
	return iam.isAuthEnabled
}

func (iam *IdentityAccessManagement) AuthRequest(r *http.Request, target string, keyId string) (*Identity, error) {
	var identity *Identity
	var err error
	var found bool
	switch getRequestAuthType(r) {
	case authTypeUnknown:
		return identity, fmt.Errorf("AccessDeniedException")
	case authTypeSigned:
		identity, err = iam.reqSignatureV4Verify(r)
	case authTypeAnonymous:
		identity, found = iam.lookupAnonymous()
		if !found {
			return identity, fmt.Errorf("AccessDeniedException")
		}
	default:
		return identity, fmt.Errorf("NotAuthorized")
	}

	if err != nil {
		return identity, err
	}

	if !identity.canDo(target, keyId) {
		return identity, fmt.Errorf("AccessDeniedException")
	}

	return identity, nil
}

func (iam *IdentityAccessManagement) lookupAnonymous() (identity *Identity, found bool) {
	for _, ident := range iam.identities {
		if ident.isAnonymous() {
			return ident, true
		}
	}
	return nil, false
}

func (iam *IdentityAccessManagement) lookupByAccessKey(accessKey string) (identity *Identity, cred *Credential, found bool) {
	for _, ident := range iam.identities {
		for _, cred := range ident.Credentials {
			if cred.AccessKey == accessKey {
				return ident, cred, true
			}
		}
	}
	return nil, nil, false
}

func (iam *IdentityAccessManagement) LoadConfigurationFromFile(fileName string) error {
	content, readErr := os.ReadFile(fileName)
	if readErr != nil {
		return fmt.Errorf("fail to read %s : %v", fileName, readErr)
	}
	return yaml.Unmarshal(content, &iam.identities)
}

func (identity *Identity) canDo(target string, keyId string) bool {
	if identity.isAdmin() {
		return true
	}
	limitedBykeyId := target + ":" + keyId
	for _, t := range identity.Targets {
		if t == target {
			return true
		}
		if t == limitedBykeyId {
			return true
		}
	}
	return false
}

func (iam *IdentityAccessManagement) reqSignatureV4Verify(r *http.Request) (*Identity, error) {
	sha256sum := getContentSha256Cksum(r)
	return iam.doesSignatureMatch(sha256sum, r)
}

// Returns SHA256 for calculating canonical-request.
func getContentSha256Cksum(r *http.Request) string {
	var (
		defaultSha256Cksum string
		v                  []string
		ok                 bool
	)

	// X-Amz-Content-Sha256, if not set in signed requests, checksum
	// will default to sha256([]byte("")).
	defaultSha256Cksum = emptySHA256
	v, ok = r.Header["X-Amz-Content-Sha256"]

	// We found 'X-Amz-Content-Sha256' return the captured value.
	if ok {
		return v[0]
	}

	// We couldn't find 'X-Amz-Content-Sha256'.
	return defaultSha256Cksum
}

// Verify authorization header - http://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html
func (iam *IdentityAccessManagement) doesSignatureMatch(hashedPayload string, r *http.Request) (*Identity, error) {

	// Copy request.
	req := *r

	// Save authorization header.
	v4Auth := req.Header.Get("Authorization")

	// Parse signature version '4' header.
	signV4Values, err := parseSignV4(v4Auth)
	if err != nil {
		return nil, err
	}

	// Extract all the signed headers along with its values.
	extractedSignedHeaders, errCode := extractSignedHeaders(signV4Values.SignedHeaders, r)
	if errCode != nil {
		return nil, errCode
	}

	// Verify if the access key id matches.
	identity, cred, found := iam.lookupByAccessKey(signV4Values.Credential.accessKey)
	if !found {
		return nil, fmt.Errorf("IncompleteSignature")
	}

	// Extract date, if not present throw error.
	var date string
	if date = req.Header.Get(http.CanonicalHeaderKey("X-Amz-Date")); date == "" {
		if date = r.Header.Get("Date"); date == "" {
			return nil, fmt.Errorf("IncompleteSignature")
		}
	}
	// Parse date header.
	t, e := time.Parse(iso8601Format, date)
	if e != nil {
		return nil, fmt.Errorf("IncompleteSignature")
	}

	// Query string.
	queryStr := req.URL.Query().Encode()

	// Get hashed Payload
	if signV4Values.Credential.scope.service != "s3" && hashedPayload == emptySHA256 && r.Body != nil {
		buf, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewBuffer(buf))
		b, _ := io.ReadAll(bytes.NewBuffer(buf))
		if len(b) != 0 {
			bodyHash := sha256.Sum256(b)
			hashedPayload = hex.EncodeToString(bodyHash[:])
		}
	}

	// Get canonical request.
	canonicalRequest := getCanonicalRequest(extractedSignedHeaders, hashedPayload, queryStr, req.URL.Path, req.Method)

	// Get string to sign from canonical request.
	stringToSign := getStringToSign(canonicalRequest, t, signV4Values.Credential.getScope())

	// Get hmac signing key.
	signingKey := getSigningKey(cred.SecretKey,
		signV4Values.Credential.scope.date,
		signV4Values.Credential.scope.region,
		signV4Values.Credential.scope.service)

	// Calculate signature.
	newSignature := getSignature(signingKey, stringToSign)

	// Verify if signature match.
	if !compareSignatureV4(newSignature, signV4Values.Signature) {
		return nil, fmt.Errorf("IncompleteSignature")
	}

	// Return error none.
	return identity, nil
}

// credentialHeader data type represents structured form of Credential
// string from authorization header.
type credentialHeader struct {
	accessKey string
	scope     struct {
		date    time.Time
		region  string
		service string
		request string
	}
}

// Return scope string.
func (c credentialHeader) getScope() string {
	return strings.Join([]string{
		c.scope.date.Format(yyyymmdd),
		c.scope.region,
		c.scope.service,
		c.scope.request,
	}, "/")
}

// signValues data type represents structured form of AWS Signature V4 header.
type signValues struct {
	Credential    credentialHeader
	SignedHeaders []string
	Signature     string
}

func contains(list []string, elem string) bool {
	for _, t := range list {
		if t == elem {
			return true
		}
	}
	return false
}

// extractSignedHeaders extract signed headers from Authorization header
func extractSignedHeaders(signedHeaders []string, r *http.Request) (http.Header, error) {
	reqHeaders := r.Header
	// find whether "host" is part of list of signed headers.
	// if not return ErrUnsignedHeaders. "host" is mandatory.
	if !contains(signedHeaders, "host") {
		return nil, fmt.Errorf("IncompleteSignature")
	}
	extractedSignedHeaders := make(http.Header)
	for _, header := range signedHeaders {
		// `host` will not be found in the headers, can be found in r.Host.
		// but its alway necessary that the list of signed headers containing host in it.
		val, ok := reqHeaders[http.CanonicalHeaderKey(header)]
		if ok {
			for _, enc := range val {
				extractedSignedHeaders.Add(header, enc)
			}
			continue
		}
		switch header {
		case "expect":
			// Golang http server strips off 'Expect' header, if the
			// client sent this as part of signed headers we need to
			// handle otherwise we would see a signature mismatch.
			// `aws-cli` sets this as part of signed headers.
			//
			// According to
			// http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.20
			// Expect header is always of form:
			//
			//   Expect       =  "Expect" ":" 1#expectation
			//   expectation  =  "100-continue" | expectation-extension
			//
			// So it safe to assume that '100-continue' is what would
			// be sent, for the time being keep this work around.
			// Adding a *TODO* to remove this later when Golang server
			// doesn't filter out the 'Expect' header.
			extractedSignedHeaders.Set(header, "100-continue")
		case "host":
			// Go http server removes "host" from Request.Header
			extractedSignedHeaders.Set(header, r.Host)
		case "transfer-encoding":
			for _, enc := range r.TransferEncoding {
				extractedSignedHeaders.Add(header, enc)
			}
		case "content-length":
			extractedSignedHeaders.Set(header, strconv.FormatInt(r.ContentLength, 10))
		default:
			return nil, fmt.Errorf("IncompleteSignature")
		}
	}
	return extractedSignedHeaders, nil
}

//	Authorization: algorithm Credential=accessKeyID/credScope, \
//	        SignedHeaders=signedHeaders, Signature=signature
func parseSignV4(v4Auth string) (sv signValues, aec error) {
	// Replace all spaced strings, some clients can send spaced
	// parameters and some won't. So we pro-actively remove any spaces
	// to make parsing easier.
	v4Auth = strings.Replace(v4Auth, " ", "", -1)
	if v4Auth == "" {
		return sv, fmt.Errorf("IncompleteSignature")
	}

	// Verify if the header algorithm is supported or not.
	if !strings.HasPrefix(v4Auth, signV4Algorithm) {
		return sv, fmt.Errorf("IncompleteSignature")
	}

	// Strip off the Algorithm prefix.
	v4Auth = strings.TrimPrefix(v4Auth, signV4Algorithm)
	authFields := strings.Split(strings.TrimSpace(v4Auth), ",")
	if len(authFields) != 3 {
		return sv, fmt.Errorf("IncompleteSignature")
	}

	// Initialize signature version '4' structured header.
	signV4Values := signValues{}

	var err error
	// Save credential values.
	signV4Values.Credential, err = parseCredentialHeader(authFields[0])
	if err != nil {
		return sv, err
	}

	// Save signed headers.
	signV4Values.SignedHeaders, err = parseSignedHeader(authFields[1])
	if err != nil {
		return sv, err
	}

	// Save signature.
	signV4Values.Signature, err = parseSignature(authFields[2])
	if err != nil {
		return sv, err
	}

	// Return the structure here.
	return signV4Values, nil
}

// parse credentialHeader string into its structured form.
func parseCredentialHeader(credElement string) (ch credentialHeader, err error) {
	creds := strings.Split(strings.TrimSpace(credElement), "=")
	if len(creds) != 2 {
		return ch, fmt.Errorf("IncompleteSignature")
	}
	if creds[0] != "Credential" {
		return ch, fmt.Errorf("IncompleteSignature")
	}
	credElements := strings.Split(strings.TrimSpace(creds[1]), "/")
	if len(credElements) != 5 {
		return ch, fmt.Errorf("IncompleteSignature")
	}
	// Save access key id.
	cred := credentialHeader{
		accessKey: credElements[0],
	}
	var e error
	cred.scope.date, e = time.Parse(yyyymmdd, credElements[1])
	if e != nil {
		return ch, fmt.Errorf("IncompleteSignature")
	}

	cred.scope.region = credElements[2]
	cred.scope.service = credElements[3] // "s3"
	cred.scope.request = credElements[4] // "aws4_request"
	return cred, nil
}

// Parse signature from signature tag.
func parseSignature(signElement string) (string, error) {
	signFields := strings.Split(strings.TrimSpace(signElement), "=")
	if len(signFields) != 2 {
		return "", fmt.Errorf("IncompleteSignature")
	}
	if signFields[0] != "Signature" {
		return "", fmt.Errorf("IncompleteSignature")
	}
	if signFields[1] == "" {
		return "", fmt.Errorf("IncompleteSignature")
	}
	signature := signFields[1]
	return signature, nil
}

// Parse slice of signed headers from signed headers tag.
func parseSignedHeader(signedHdrElement string) ([]string, error) {
	signedHdrFields := strings.Split(strings.TrimSpace(signedHdrElement), "=")
	if len(signedHdrFields) != 2 {
		return nil, fmt.Errorf("IncompleteSignature")
	}
	if signedHdrFields[0] != "SignedHeaders" {
		return nil, fmt.Errorf("IncompleteSignature")
	}
	if signedHdrFields[1] == "" {
		return nil, fmt.Errorf("IncompleteSignature")
	}
	signedHeaders := strings.Split(signedHdrFields[1], ";")
	return signedHeaders, nil
}

// sumHMAC calculate hmac between two input byte array.
func sumHMAC(key []byte, data []byte) []byte {
	hash := hmac.New(sha256.New, key)
	hash.Write(data)
	return hash.Sum(nil)
}

// getSignature final signature in hexadecimal form.
func getSignature(signingKey []byte, stringToSign string) string {
	return hex.EncodeToString(sumHMAC(signingKey, []byte(stringToSign)))
}

// getSigningKey hmac seed to calculate final signature.
func getSigningKey(secretKey string, t time.Time, region string, service string) []byte {
	date := sumHMAC([]byte("AWS4"+secretKey), []byte(t.Format(yyyymmdd)))
	regionBytes := sumHMAC(date, []byte(region))
	serviceBytes := sumHMAC(regionBytes, []byte(service))
	signingKey := sumHMAC(serviceBytes, []byte("aws4_request"))
	return signingKey
}

// getStringToSign a string based on selected query values.
func getStringToSign(canonicalRequest string, t time.Time, scope string) string {
	stringToSign := signV4Algorithm + "\n" + t.Format(iso8601Format) + "\n"
	stringToSign = stringToSign + scope + "\n"
	canonicalRequestBytes := sha256.Sum256([]byte(canonicalRequest))
	stringToSign = stringToSign + hex.EncodeToString(canonicalRequestBytes[:])
	return stringToSign
}

// getCanonicalHeaders generate a list of request headers with their values
func getCanonicalHeaders(signedHeaders http.Header) string {
	var headers []string
	vals := make(http.Header)
	for k, vv := range signedHeaders {
		headers = append(headers, strings.ToLower(k))
		vals[strings.ToLower(k)] = vv
	}
	sort.Strings(headers)

	var buf bytes.Buffer
	for _, k := range headers {
		buf.WriteString(k)
		buf.WriteByte(':')
		for idx, v := range vals[k] {
			if idx > 0 {
				buf.WriteByte(',')
			}
			buf.WriteString(signV4TrimAll(v))
		}
		buf.WriteByte('\n')
	}
	return buf.String()
}

func signV4TrimAll(input string) string {
	// Compress adjacent spaces (a space is determined by
	// unicode.IsSpace() internally here) to one space and return
	return strings.Join(strings.Fields(input), " ")
}

// getSignedHeaders generate a string i.e alphabetically sorted, semicolon-separated list of lowercase request header names
func getSignedHeaders(signedHeaders http.Header) string {
	var headers []string
	for k := range signedHeaders {
		headers = append(headers, strings.ToLower(k))
	}
	sort.Strings(headers)
	return strings.Join(headers, ";")
}

var reservedObjectNames = regexp.MustCompile("^[a-zA-Z0-9-_.~/]+$")

func encodePath(pathName string) string {
	if reservedObjectNames.MatchString(pathName) {
		return pathName
	}
	var encodedPathname string
	for _, s := range pathName {
		if 'A' <= s && s <= 'Z' || 'a' <= s && s <= 'z' || '0' <= s && s <= '9' { // §2.3 Unreserved characters (mark)
			encodedPathname = encodedPathname + string(s)
			continue
		}
		switch s {
		case '-', '_', '.', '~', '/': // §2.3 Unreserved characters (mark)
			encodedPathname = encodedPathname + string(s)
			continue
		default:
			len := utf8.RuneLen(s)
			if len < 0 {
				// if utf8 cannot convert return the same string as is
				return pathName
			}
			u := make([]byte, len)
			utf8.EncodeRune(u, s)
			for _, r := range u {
				hex := hex.EncodeToString([]byte{r})
				encodedPathname = encodedPathname + "%" + strings.ToUpper(hex)
			}
		}
	}
	return encodedPathname
}

func getCanonicalRequest(extractedSignedHeaders http.Header, payload, queryStr, urlPath, method string) string {
	rawQuery := strings.Replace(queryStr, "+", "%20", -1)
	encodedPath := encodePath(urlPath)
	canonicalRequest := strings.Join([]string{
		method,
		encodedPath,
		rawQuery,
		getCanonicalHeaders(extractedSignedHeaders),
		getSignedHeaders(extractedSignedHeaders),
		payload,
	}, "\n")
	return canonicalRequest
}

func compareSignatureV4(sig1, sig2 string) bool {
	// The CTC using []byte(str) works because the hex encoding
	// is unique for a sequence of bytes. See also compareSignatureV2.
	return subtle.ConstantTimeCompare([]byte(sig1), []byte(sig2)) == 1
}
