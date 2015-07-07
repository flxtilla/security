package login

import (
	"strings"

	"github.com/thrisp/flotilla"
	"github.com/thrisp/security/user"
)

type (
	Configuration func(*Manager) error
)

func (l *Manager) Configure(conf ...Configuration) error {
	var err error
	for _, c := range conf {
		err = c(l)
	}
	return err
}

func UserLoader(fn func(string) user.User) Configuration {
	return func(l *Manager) error {
		l.userloader = fn
		return nil
	}
}

func Reloader(name string, h flotilla.Manage) Configuration {
	return func(l *Manager) error {
		l.Reloaders[name] = h
		return nil
	}
}

func WithSettings(items ...string) Configuration {
	return func(l *Manager) error {
		for _, item := range items {
			i := strings.Split(item, ":")
			key, value := i[0], i[1]
			l.Settings[strings.ToUpper(key)] = value
		}
		return nil
	}
}
