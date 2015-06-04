package user

import "errors"

type DataStore interface {
	New(string, string) (User, error)
	Get(string) User
	Put(User) (User, error)
	Delete(User) error
}

var NotImplemented = errors.New("[Security-User] Not Implemented")

func DefaultDataStore() *defaultDataStore {
	return &defaultDataStore{}
}

type defaultDataStore struct{}

func (d *defaultDataStore) New(name string, password string) (User, error) {
	return AnonymousUser, NotImplemented
}

func (d *defaultDataStore) Get(string) User {
	return AnonymousUser
}

func (d *defaultDataStore) Put(User) (User, error) {
	return nil, NotImplemented
}

func (d *defaultDataStore) Delete(User) error {
	return NotImplemented
}
