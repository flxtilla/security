package token

import (
	"crypto/aes"
	"crypto/cipher"
	cr "crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	mr "math/rand"
	"strings"
	"time"
)

type Signatory interface {
	Name() string
	Token(...string) *Token
	Valid(string) (*Token, error)
	SignedString(...string) string
	Signer
}

func NewSignatory(name, timestamp, key string, sr Signer) Signatory {
	return &signatory{
		name:            name,
		timestampFormat: timestamp,
		timestampClaim:  fmt.Sprintf("tsf:%s", timestamp),
		key:             mkEncryptionKey(key),
		Signer:          sr,
	}
}

func mkEncryptionKey(key string) []byte {
	var ret string
	k := len(key)
	switch k {
	case 16, 24, 32:
		ret = key
	default:
		panic("Length of signatory encryption key MUST be 16, 24, 32")
	}
	return []byte(ret)
}

type signatory struct {
	name            string
	timestampFormat string
	timestampClaim  string
	key             []byte
	Signer
}

func (s *signatory) Name() string {
	return s.name
}

func (s *signatory) Token(items ...string) *Token {
	tkn := New(s)
	items = append(items, s.timestampClaim, s.iat())
	mkClaims(tkn, items)
	return tkn
}

func (s *signatory) iat() string {
	return fmt.Sprintf("iat:%s", time.Now().Format(s.timestampFormat))
}

func (s *signatory) SignedString(claims ...string) string {
	signed, err := s.Token(claims...).SignedString(s.Signer.Key())
	if err != nil {
		return err.Error()
	}
	return s.Encrypt(signed)
}

func mkClaims(t *Token, items []string) {
	for _, v := range items {
		sp := strings.Split(v, ":")
		if len(sp) == 2 {
			t.Claims[sp[0]] = sp[1]
		}
	}
}

func (s *signatory) Valid(token string) (*Token, error) {
	tkn, err := s.Decrypt(token)
	if err != nil {
		return nil, err
	}
	return Parse(tkn, s.Signer.Keyfunc())
}

func (s *signatory) Encrypt(tokenString string) string {
	c, err := aes.NewCipher([]byte(s.key))
	if err != nil {
		panic(err.Error())
	}
	out := make([]byte, aes.BlockSize+len(tokenString))
	iv := out[:aes.BlockSize]
	if _, err := io.ReadFull(cr.Reader, iv); err != nil {
		panic(err)
	}
	cfb := cipher.NewCFBEncrypter(c, iv)
	cfb.XORKeyStream(out[aes.BlockSize:], []byte(tokenString))
	return base64.URLEncoding.EncodeToString(out)
}

func (s *signatory) Decrypt(tokenString string) (string, error) {
	tkn, err := base64.URLEncoding.DecodeString(tokenString)
	if err != nil {
		return "", err
	}
	c, err := aes.NewCipher([]byte(s.key))
	if err != nil {
		return "", err
	}
	if len(tkn) < aes.BlockSize {
		return "", ErrTokenLength
	}
	iv := tkn[:aes.BlockSize]
	tkn = tkn[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(c, iv)
	cfb.XORKeyStream(tkn, tkn)
	return string(tkn), nil
}

func init() {
	mr.Seed(time.Now().UTC().UnixNano())
}
