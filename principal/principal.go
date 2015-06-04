package principal

import "github.com/thrisp/flotilla"

type Manager struct {
	DataStore
	ctx          flotilla.Ctx
	loaders      []IdentityLoader
	handlers     []IdentityHandler
	unauthorized flotilla.Manage
}

func New(c ...Conf) *Manager {
	p := &Manager{}
	c = append(c, IdentityHandle(defaulthandler))
	p.Configure(c...)
	if p.DataStore == nil {
		p.DataStore = DefaultDataStore()
	}
	return p
}

func (p *Manager) Init(app *flotilla.App) {
	app.Configuration = append(app.Configuration, flotilla.Extensions(p.mkfxtension()))
	app.UseAt(0, p.OnRequest)
}

func mkextension(p *Manager) map[string]interface{} {
	return map[string]interface{}{
		"principal":       func(c flotilla.Ctx) *Manager { return p },
		"currentidentity": func(c flotilla.Ctx) Identity { return currentidentity(c) },
	}
}

func (p *Manager) mkfxtension() flotilla.Fxtension {
	return flotilla.MakeFxtension("fxprincipal", mkextension(p))
}

func (p *Manager) Change(i Identity) {
	p.Handle(i)
}

func (p *Manager) LoadIdentity(c flotilla.Ctx) Identity {
	identity := Anonymous
	for _, loader := range p.loaders {
		identity = loader(c)
	}
	p.Handle(identity)
	return identity
}

func (p *Manager) Handle(i Identity) {
	for _, h := range p.handlers {
		h(i, p.ctx)
	}
}

func (p *Manager) OnRequest(c flotilla.Ctx) {
	p.ctx = c
	p.LoadIdentity(c)
}

func (p *Manager) Unauthorized(c flotilla.Ctx) {
	if p.unauthorized != nil {
		p.unauthorized(c)
	} else {
		c.Call("status", 401)
	}
}

func manager(c flotilla.Ctx) *Manager {
	p, _ := c.Call("principal")
	return p.(*Manager)
}

// Sufficient wraps a flotilla HandlerFunc with permissions, allowing
// access if the current identity is allowed for any given permission.
func Sufficient(h flotilla.Manage, perms ...Permission) flotilla.Manage {
	return func(c flotilla.Ctx) {
		identity := currentidentity(c)
		permitted := false
		for _, p := range perms {
			if p.Allows(identity) {
				permitted = true
				h(c)
			}
		}
		if !permitted {
			manager(c).Unauthorized(c)
		}
	}
}

// Necessary wraps a flotilla HandlerFunc with permissions, requiring
// that the current identity satifies all permissions fully before access.
func Necessary(h flotilla.Manage, permissions ...Permission) flotilla.Manage {
	return func(c flotilla.Ctx) {
		identity := currentidentity(c)
		permitted := true
		for _, permission := range permissions {
			if !permission.Requires(identity) {
				permitted = false
				manager(c).Unauthorized(c)
			}
		}
		if permitted {
			h(c)
		}
	}
}
