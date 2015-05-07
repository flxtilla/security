package user

import (
	"github.com/thrisp/security/principal"
)

type User interface {
	principal.Identity
	Authenticated() bool
	Active() bool
	Anonymous() bool
	Id() string
}

var AnonymousUser = &anonymoususer{Identity: principal.Anonymous}

type anonymoususer struct {
	principal.Identity
}

func (a anonymoususer) Authenticated() bool {
	return false
}

func (a anonymoususer) Active() bool {
	return false
}

func (a anonymoususer) Anonymous() bool {
	return true
}

func (a anonymoususer) Id() string {
	return "anonymous"
}
