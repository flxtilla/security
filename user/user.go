package user

import (
	"github.com/thrisp/security/principal"
)

type User interface {
	principal.Identity
	Identifiable
	Updateable
	Authenticateable
	Tokenable
}

type Identifiable interface {
	Id() string
	Email() string
	Anonymous() bool
	Confirmed() bool
	Active() bool
}

type Updateable interface {
	Update(string, string) error
}

type Authenticateable interface {
	Authenticate(string) error
	Authenticated() bool
}

type Tokenable interface {
	Token(string) []byte
	Validate(string, []byte) bool
}

var AnonymousUser = &anonymoususer{Identity: principal.Anonymous}

type anonymoususer struct {
	principal.Identity
}

func (a anonymoususer) Id() string {
	return "anonymous"
}

func (a anonymoususer) Email() string {
	return ""
}

func (a anonymoususer) Anonymous() bool {
	return true
}

func (a anonymoususer) Confirmed() bool {
	return false
}

func (a anonymoususer) Active() bool {
	return false
}

func (a anonymoususer) Update(string, string) error {
	return NotImplemented
}

func (a anonymoususer) Authenticate(password string) error {
	return NotImplemented
}

func (a anonymoususer) Authenticated() bool {
	return false
}

func (a anonymoususer) Token(key string) []byte {
	return []byte("")
}

func (a anonymoususer) Validate(key string, token []byte) bool {
	return false
}
