package principal

import (
	"github.com/thrisp/flotilla"
)

type (
	Configuration func(*Manager) error
)

func (p *Manager) Configure(c ...Configuration) error {
	var err error
	for _, fn := range c {
		err = fn(p)
	}
	if err != nil {
		return err
	}
	return nil
}

func IdentityLoad(fns ...IdentityLoader) Configuration {
	return func(p *Manager) error {
		p.loaders = append(p.loaders, fns...)
		return nil
	}
}

func IdentityHandle(fns ...IdentityHandler) Configuration {
	return func(p *Manager) error {
		p.handlers = append(p.handlers, fns...)
		return nil
	}
}

func IdentityRemove(fns ...IdentityRemover) Configuration {
	return func(p *Manager) error {
		p.removers = append(p.removers, fns...)
		return nil
	}
}

func Unauthorized(fn flotilla.Manage) Configuration {
	return func(p *Manager) error {
		p.unauthorized = fn
		return nil
	}
}
