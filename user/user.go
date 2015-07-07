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
	Confirmable
}

type Identifiable interface {
	Id() string
	Email() string
	Anonymous() bool
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
	Token(string) string
	Validate(string, string) bool
}

type Confirmable interface {
	Confirm()
	Confirmed() bool
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

func (a anonymoususer) Confirm() {}

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

func (a anonymoususer) Token(key string) string {
	return ""
}

func (a anonymoususer) Validate(key string, token string) bool {
	return false
}
