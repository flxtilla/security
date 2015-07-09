package token

var signingMethods = map[string]func() SigningMethod{}

type SigningMethod interface {
	Verify(string, string, interface{}) error
	Sign(string, interface{}) (string, error)
	Alg() string
}

func RegisterSigningMethod(alg string, f func() SigningMethod) {
	signingMethods[alg] = f
}

func GetSigningMethod(alg string) (method SigningMethod) {
	if methodF, ok := signingMethods[alg]; ok {
		method = methodF()
	}
	return
}

type Signer interface {
	SigningMethod
	Key() []byte
	Keyfunc() Keyfunc
}

func NewSigner(method, key string) Signer {
	return &signer{
		SigningMethod: GetSigningMethod(method),
		key:           []byte(key),
	}
}

type signer struct {
	SigningMethod
	key []byte
}

func (s *signer) Key() []byte {
	return s.key
}

func (s *signer) Keyfunc() Keyfunc {
	return func(*Token) (interface{}, error) {
		return s.key, nil
	}
}
