package token

import (
	"crypto"
	"crypto/hmac"
	"errors"
)

type SigningMethodHMAC struct {
	Name string
	Hash crypto.Hash
}

func (m *SigningMethodHMAC) Verify(signingString, signature string, key interface{}) error {
	if k, ok := key.([]byte); ok {
		var sig []byte
		var err error
		if sig, err = DecodeSegment(signature); err == nil {
			if !m.Hash.Available() {
				return ErrHashUnavailable
			}

			hasher := hmac.New(m.Hash.New, k)
			hasher.Write([]byte(signingString))

			if !hmac.Equal(sig, hasher.Sum(nil)) {
				err = ErrSignatureInvalid
			}
		}
		return err
	}

	return ErrInvalidKey
}

func (m *SigningMethodHMAC) Sign(signingString string, key interface{}) (string, error) {
	if k, ok := key.([]byte); ok {
		if !m.Hash.Available() {
			return "", ErrHashUnavailable
		}

		hasher := hmac.New(m.Hash.New, k)
		hasher.Write([]byte(signingString))

		return EncodeSegment(hasher.Sum(nil)), nil
	}

	return "", ErrInvalidKey
}

func (m *SigningMethodHMAC) Alg() string {
	return m.Name
}

// Specific instances for HS256 and company
var (
	SigningMethodHS256  *SigningMethodHMAC
	SigningMethodHS384  *SigningMethodHMAC
	SigningMethodHS512  *SigningMethodHMAC
	ErrSignatureInvalid = errors.New("signature is invalid")
)

func init() {
	// HS256
	SigningMethodHS256 = &SigningMethodHMAC{"HS256", crypto.SHA256}
	RegisterSigningMethod(SigningMethodHS256.Alg(), func() SigningMethod {
		return SigningMethodHS256
	})

	// HS384
	SigningMethodHS384 = &SigningMethodHMAC{"HS384", crypto.SHA384}
	RegisterSigningMethod(SigningMethodHS384.Alg(), func() SigningMethod {
		return SigningMethodHS384
	})

	// HS512
	SigningMethodHS512 = &SigningMethodHMAC{"HS512", crypto.SHA512}
	RegisterSigningMethod(SigningMethodHS512.Alg(), func() SigningMethod {
		return SigningMethodHS512
	})
}
