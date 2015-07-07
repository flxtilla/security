package principal

import (
	"encoding/gob"

	"github.com/thrisp/flotilla"
)

type IdentityLoader func(flotilla.Ctx) Identity

type IdentityHandler func(Identity, flotilla.Ctx)

func defaulthandler(i Identity, c flotilla.Ctx) {
	c.Call("set", "identity", i)
}

type IdentityRemover func(flotilla.Ctx)

func defaultremover(c flotilla.Ctx) {
	c.Call("set", "identity", Anonymous)
}

var Anonymous = NewIdentity("anonymous", "anonymous")

type Identity interface {
	Tag() string
	Provides(...interface{}) Set
	Can(Permission) bool
	Must(Permission) bool
}

type identity struct {
	Tagged   string
	Provided Set
}

func NewIdentity(tag string, provided ...interface{}) Identity {
	provided = append(provided, "anonymous")
	return &identity{Tagged: tag, Provided: NewSet(provided...)}
}

func (i *identity) Tag() string {
	return i.Tagged
}

func (i *identity) Provides(p ...interface{}) Set {
	i.Provided.Add(p...)
	return i.Provided
}

func (i *identity) Can(p Permission) bool {
	return p.Allows(i)
}

func (i *identity) Must(p Permission) bool {
	return p.Requires(i)
}

func currentidentity(c flotilla.Ctx) Identity {
	identity, _ := c.Call("get", "identity")
	if identity != nil {
		return identity.(Identity)
	}
	return Anonymous
}

func init() {
	gob.Register(&identity{})
	gob.Register(&set{})
}
