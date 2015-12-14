package security

import (
	"strings"

	"github.com/thrisp/security/user"
)

var ConfigurationError = Srror(`configuration error: %s`).Out

type Configuration func(*Manager) error

func (m *Manager) Configuration(conf ...Configuration) error {
	var err error
	for _, c := range conf {
		err = c(m)
	}
	return err
}

func WithUserDataStore(u user.DataStore) Configuration {
	return func(s *Manager) error {
		s.DataStore = u
		return nil
	}
}

func WithSettings(items ...string) Configuration {
	return func(s *Manager) error {
		for _, item := range items {
			i := strings.Split(item, ":")
			key, value := i[0], i[1]
			s.Settings[strings.ToUpper(key)] = value
		}
		return nil
	}
}

func WithEmailer(e Emailer) Configuration {
	return func(s *Manager) error {
		s.Emailer = e
		return nil
	}
}
