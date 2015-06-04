package principal

import (
	"encoding/gob"

	"github.com/thrisp/flotilla"
)

//"gopkg.in/fatih/set.v0"

type IdentityLoader func(flotilla.Ctx) Identity

func sessionloader(c flotilla.Ctx) Identity {
	iid, _ := c.Call("getsession", "identity_id")
	if iid != nil {
		id := iid.(string)
		return NewIdentity(id, id)
	}
	return Anonymous
}

type IdentityHandler func(Identity, flotilla.Ctx)

func defaulthandler(i Identity, c flotilla.Ctx) {
	c.Call("set", "identity", i)
}

func sessionhandler(i Identity, c flotilla.Ctx) {
	c.Call("setsession", "identity_id", i.Tag())
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
