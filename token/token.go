// Package token is an implementation of https://github.com/dgrijalva/jwt-go
package token

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

var TimeFunc = time.Now

var TimeZone *time.Location = time.Now().Local().Location()

type Keyfunc func(*Token) (interface{}, error)

type Token struct {
	Raw       string
	Method    SigningMethod
	Header    map[string]interface{}
	Claims    map[string]interface{}
	Signature string
	Valid     bool
}

func New(method SigningMethod) *Token {
	return &Token{
		Header: map[string]interface{}{
			"typ": "JWT",
			"alg": method.Alg(),
		},
		Claims: make(map[string]interface{}),
		Method: method,
	}
}

func (t *Token) SignedString(key interface{}) (string, error) {
	var sig, sstr string
	var err error
	if sstr, err = t.SigningString(); err != nil {
		return "", err
	}
	if sig, err = t.Method.Sign(sstr, key); err != nil {
		return "", err
	}
	return strings.Join([]string{sstr, sig}, "."), nil
}

func (t *Token) SigningString() (string, error) {
	var err error
	parts := make([]string, 2)
	for i, _ := range parts {
		var source map[string]interface{}
		if i == 0 {
			source = t.Header
		} else {
			source = t.Claims
		}

		var jsonValue []byte
		if jsonValue, err = json.Marshal(source); err != nil {
			return "", err
		}

		parts[i] = EncodeSegment(jsonValue)
	}
	return strings.Join(parts, "."), nil
}

func Parse(tokenString string, keyFunc Keyfunc) (*Token, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, &ValidationError{err: "token contains an invalid number of segments", Errors: ValidationErrorMalformed}
	}

	var err error
	token := &Token{Raw: tokenString}
	// parse Header
	var headerBytes []byte
	if headerBytes, err = DecodeSegment(parts[0]); err != nil {
		return token, &ValidationError{err: err.Error(), Errors: ValidationErrorMalformed}
	}
	if err = json.Unmarshal(headerBytes, &token.Header); err != nil {
		return token, &ValidationError{err: err.Error(), Errors: ValidationErrorMalformed}
	}

	// parse Claims
	var claimBytes []byte
	if claimBytes, err = DecodeSegment(parts[1]); err != nil {
		return token, &ValidationError{err: err.Error(), Errors: ValidationErrorMalformed}
	}
	if err = json.Unmarshal(claimBytes, &token.Claims); err != nil {
		return token, &ValidationError{err: err.Error(), Errors: ValidationErrorMalformed}
	}

	// Lookup signature method
	if method, ok := token.Header["alg"].(string); ok {
		if token.Method = GetSigningMethod(method); token.Method == nil {
			return token, &ValidationError{err: "signing method (alg) is unavailable.", Errors: ValidationErrorUnverifiable}
		}
	} else {
		return token, &ValidationError{err: "signing method (alg) is unspecified.", Errors: ValidationErrorUnverifiable}
	}

	// Lookup key
	var key interface{}
	if keyFunc == nil {
		// keyFunc was not provided.  short circuiting validation
		return token, &ValidationError{err: "no Keyfunc was provided.", Errors: ValidationErrorUnverifiable}
	}
	if key, err = keyFunc(token); err != nil {
		// keyFunc returned an error
		return token, &ValidationError{err: err.Error(), Errors: ValidationErrorUnverifiable}
	}

	// Check expiration times
	vErr := &ValidationError{}
	now := TimeFunc()
	var format string
	format, ok := token.Claims["timestamp_format"].(string)
	if !ok {
		format = time.UnixDate
	}
	if exp, ok := token.Claims["exp"].(string); ok {
		expires, err := time.ParseInLocation(format, exp, TimeZone)
		if err == nil {
			if now.After(expires) {
				vErr.err = "token is expired"
				vErr.Errors |= ValidationErrorExpired
			}
		}
	}
	if nbf, ok := token.Claims["nbf"].(string); ok {
		before, err := time.ParseInLocation(format, nbf, TimeZone)
		if err == nil {
			if now.Before(before) {
				vErr.err = "token is not valid yet"
				vErr.Errors |= ValidationErrorNotValidYet
			}
		}
	}

	// Perform validation
	if err = token.Method.Verify(strings.Join(parts[0:2], "."), parts[2], key); err != nil {
		vErr.err = err.Error()
		vErr.Errors |= ValidationErrorSignatureInvalid
	}

	if vErr.valid() {
		token.Valid = true
		return token, nil
	}

	return token, vErr
}

func ParseFromRequest(req *http.Request, keyFunc Keyfunc) (token *Token, err error) {
	// Look for an Authorization header
	if ah := req.Header.Get("Authorization"); ah != "" {
		// Should be a bearer token
		if len(ah) > 6 && strings.ToUpper(ah[0:6]) == "BEARER" {
			return Parse(ah[7:], keyFunc)
		}
	}

	// Look for "access_token" parameter
	req.ParseMultipartForm(10e6)
	if tokStr := req.Form.Get("access_token"); tokStr != "" {
		return Parse(tokStr, keyFunc)
	}

	return nil, ErrNoTokenInRequest

}

func EncodeSegment(seg []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(seg), "=")
}

func DecodeSegment(seg string) ([]byte, error) {
	if l := len(seg) % 4; l > 0 {
		seg += strings.Repeat("=", 4-l)
	}

	return base64.URLEncoding.DecodeString(seg)
}
