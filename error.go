package security

import "fmt"

type securityError struct {
	err  string
	vals []interface{}
}

func (m *securityError) Error() string {
	return fmt.Sprintf("%s", fmt.Sprintf(m.err, m.vals...))
}

func (m *securityError) Out(vals ...interface{}) *securityError {
	m.vals = vals
	return m
}

func Srror(err string) *securityError {
	return &securityError{err: err}
}
