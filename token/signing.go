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
