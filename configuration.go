package security

import "strings"

type Configuration func(*Manager) error

func (m *Manager) Configuration(conf ...Configuration) error {
	var err error
	for _, c := range conf {
		err = c(m)
	}
	return err
}

func WithDataStore(d DataStore) Configuration {
	return func(s *Manager) error {
		s.DataStore = d
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
