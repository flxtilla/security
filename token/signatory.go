package token

import "strings"

type Signatory interface {
	Name() string
	Token(...string) *Token
	Valid(string) (*Token, error)
	SignedString(...string) string
}

func NewSignatory(name, method, key string) Signatory {
	return &signatory{
		name:    name,
		signing: GetSigningMethod(method),
		key:     []byte(key),
	}
}

type signatory struct {
	name    string
	signing SigningMethod
	key     []byte
}

func (s *signatory) Name() string {
	return s.name
}

func (s *signatory) Token(items ...string) *Token {
	tkn := New(s.signing)
	mkClaims(tkn, items)
	return tkn
}

func (s *signatory) SignedString(claims ...string) string {
	signed, err := s.Token(claims...).SignedString(s.key)
	if err != nil {
		return err.Error()
	}
	return signed
}

func mkClaims(t *Token, items []string) {
	for _, v := range items {
		sp := strings.Split(v, ":")
		if len(sp) == 2 {
			t.Claims[sp[0]] = sp[1]
		}
	}
}

func (s *signatory) keyfunc() Keyfunc {
	return func(*Token) (interface{}, error) {
		return s.key, nil
	}
}

func (s *signatory) Valid(token string) (*Token, error) {
	return Parse(token, s.keyfunc())
}