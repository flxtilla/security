package security

import (
	"strings"

	"github.com/thrisp/security/principal"
	"github.com/thrisp/security/user"
)

type Configuration func(*Manager) error

func (m *Manager) Configuration(conf ...Configuration) error {
	var err error
	for _, c := range conf {
		err = c(m)
	}
	return err
}

func UserDataStore(u user.DataStore) Configuration {
	return func(s *Manager) error {
		s.login.DataStore = u
		return nil
	}
}

func PrincipalDataStore(p principal.DataStore) Configuration {
	return func(s *Manager) error {
		s.principal.DataStore = p
		return nil
	}
}

func Settings(items ...string) Configuration {
	return func(s *Manager) error {
		for _, item := range items {
			i := strings.Split(item, ":")
			key, value := i[0], i[1]
			s.Settings[strings.ToUpper(key)] = value
		}
		return nil
	}
}
